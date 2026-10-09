// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pre-attach takes the slowest part of moving an RWO volume out of the
// freeze.
//
// Measured on this lab (Cinder/iSCSI, Kubernetes 1.37): detach 3.2 s, attach
// 13.1 s. Kubernetes' attach/detach controller only attaches the volume to the
// target after it has been detached from the source (RWO), so both would sit
// inside the freeze.
//
// While pre-copy runs, the target agent creates the VolumeAttachment that the
// attach/detach controller will later create itself – same name, same spec.
// The CSI external-attacher processes it and attaches the volume to the target
// VM in advance. This only works for volume types that allow multi-attach
// (Cinder: volume type with multiattach="<is> True"; EBS: io2 Multi-Attach);
// for others the attach fails and the object is removed again. The volume is
// never *mounted* on the target before the source has unmounted it: kubelet
// only mounts for a pod, and the attach/detach controller only reports the
// volume attached to the target after the source detach finished (RWO
// semantics are untouched).
//
// When the attach/detach controller later attaches to the target, it finds an
// existing, attached VolumeAttachment with the expected name and adopts it.
// CSI ControllerPublish is idempotent for an instance the volume is already
// attached to (cinder-csi: "Disk %s is already attached to instance %s").

// attachmentName mirrors kubelet/attach-detach controller naming
// (pkg/volume/csi/csi_attacher.go: getAttachmentName).
func attachmentName(volumeHandle, driver, node string) string {
	return fmt.Sprintf("csi-%x", sha256.Sum256([]byte(volumeHandle+driver+node)))
}

// preAttached describes one VolumeAttachment we created.
type preAttached struct {
	Name, PV string
	// Volume is the pod volume name (status.volumes[].name).
	Volume string
}

// preAttach creates VolumeAttachments for all RWO CSI volumes of pod on this
// node and waits (bounded) until they are attached. Volumes whose attach fails
// (e.g. no multi-attach support) are rolled back and skipped – the migration
// then simply pays the attach inside the freeze, as without pre-attach.
//
// Skipped: RWX/ROX volumes – Kubernetes attaches them to several nodes at
// once, so the attach for the warm replacement starts during pre-copy anyway
// – and drivers that attach nothing (CSIDriver attachRequired: false, e.g.
// NFS): nobody would ever answer the VolumeAttachment, and the target would
// wait for the timeout before it reports ready (measured: pre-copy started
// 90 s late with an NFS volume).
func (j *targetJob) preAttach(ctx context.Context, pod *corev1.Pod) []preAttached {
	var done []preAttached
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		if err := j.a.Client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: v.PersistentVolumeClaim.ClaimName}, pvc); err != nil ||
			pvc.Spec.VolumeName == "" || sharedAccess(pvc) {
			continue
		}
		pv := &corev1.PersistentVolume{}
		if err := j.a.Client.Get(ctx, types.NamespacedName{Name: pvc.Spec.VolumeName}, pv); err != nil || pv.Spec.CSI == nil ||
			!j.attachRequired(ctx, pv.Spec.CSI.Driver) {
			continue
		}
		name := attachmentName(pv.Spec.CSI.VolumeHandle, pv.Spec.CSI.Driver, j.a.NodeName)
		pvName := pv.Name
		va := &storagev1.VolumeAttachment{}
		va.Name = name
		va.Spec = storagev1.VolumeAttachmentSpec{
			Attacher: pv.Spec.CSI.Driver,
			NodeName: j.a.NodeName,
			Source:   storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvName},
		}
		va.Annotations = map[string]string{"paguro.dev/pre-attach": string(j.m.UID)}
		start := time.Now()
		if err := j.a.Client.Create(ctx, va); err != nil && !apierrors.IsAlreadyExists(err) {
			j.log.Warn("pre-attach: cannot create VolumeAttachment", "pv", pv.Name, "err", err)
			continue
		}
		ok, msg := j.waitAttached(ctx, name, 90*time.Second)
		if !ok {
			j.log.Info("pre-attach not possible, volume will be attached during the freeze", "pv", pv.Name, "reason", msg)
			_ = j.a.Client.Delete(ctx, &storagev1.VolumeAttachment{ObjectMeta: va.ObjectMeta})
			continue
		}
		j.log.Info("volume pre-attached to target", "pv", pv.Name, "attachment", name, "ms", ms(time.Since(start)))
		done = append(done, preAttached{Name: name, PV: pv.Name, Volume: v.Name})
	}
	return done
}

// sharedAccess: the volume may be used on several nodes at once.
func sharedAccess(pvc *corev1.PersistentVolumeClaim) bool {
	for _, m := range pvc.Status.AccessModes {
		if m == corev1.ReadWriteMany || m == corev1.ReadOnlyMany {
			return true
		}
	}
	return false
}

// attachRequired reports whether the CSI driver attaches volumes to nodes.
// Without a CSIDriver object Kubernetes assumes it does; so do we when the
// object cannot be read.
func (j *targetJob) attachRequired(ctx context.Context, driver string) bool {
	d := &storagev1.CSIDriver{}
	if err := j.a.Client.Get(ctx, client.ObjectKey{Name: driver}, d); err != nil {
		return true
	}
	return d.Spec.AttachRequired == nil || *d.Spec.AttachRequired
}

func (j *targetJob) waitAttached(ctx context.Context, name string, timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		va := &storagev1.VolumeAttachment{}
		if err := j.a.Client.Get(ctx, client.ObjectKey{Name: name}, va); err == nil {
			if va.Status.Attached {
				return true, ""
			}
			if va.Status.AttachError != nil {
				return false, va.Status.AttachError.Message
			}
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err().Error()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return false, "timeout"
}

// releasePreAttached removes our VolumeAttachments after a failed or
// rolled-back migration. On success the attach/detach controller has adopted
// them and they must stay.
func (a *Agent) releasePreAttached(ctx context.Context, migrationUID types.UID) {
	list := &storagev1.VolumeAttachmentList{}
	if err := a.Client.List(ctx, list); err != nil {
		return
	}
	for i := range list.Items {
		va := &list.Items[i]
		if va.Annotations["paguro.dev/pre-attach"] == string(migrationUID) && va.Spec.NodeName == a.NodeName {
			_ = a.Client.Delete(ctx, va)
			a.Log.Info("pre-attach rolled back", "attachment", va.Name)
		}
	}
}
