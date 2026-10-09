// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package v1alpha1

import "paguro.dev/paguro/pkg/names"

// Re-exports from pkg/names (documented there).
const (
	LabelMigratable             = names.LabelMigratable
	AnnotationRestore           = names.AnnotationRestore
	AnnotationRestoreID         = names.AnnotationRestoreID
	AnnotationMigrating         = names.AnnotationMigrating
	AnnotationTCP               = names.AnnotationTCP
	AnnotationOldIP             = names.AnnotationOldIP
	AnnotationSkippedInit       = names.AnnotationSkippedInit
	AnnotationStickyIP          = names.AnnotationStickyIP
	SchedulingGateCommit        = names.SchedulingGateCommit
	SchedulerNameBind           = names.SchedulerNameBind
	AnnotationNodeCPUFlags      = names.AnnotationNodeCPUFlags
	AnnotationCPUBaseline       = names.AnnotationCPUBaseline
	AnnotationNodeCPUModel      = names.AnnotationNodeCPUModel
	AnnotationNodeAgent         = names.AnnotationNodeAgent
	AnnotationNodeAgentVersion  = names.AnnotationNodeAgentVersion
	AnnotationNodeAgentDraining = names.AnnotationNodeAgentDraining
	AnnotationNodeCRIU          = names.AnnotationNodeCRIU
	AnnotationNodePhantom       = names.AnnotationNodePhantom
	AnnotationNodeCNI           = names.AnnotationNodeCNI
	AnnotationNodeCommitGate    = names.AnnotationNodeCommitGate
	AnnotationNodeSubnets       = names.AnnotationNodeSubnets
	AnnotationNodeTerminatesAt  = names.AnnotationNodeTerminatesAt
	TaintAgentNotReady          = names.TaintAgentNotReady
	AnnotationNetwork           = names.AnnotationNetwork
	AnnotationTestFault         = names.AnnotationTestFault
	RuntimeClassName            = names.RuntimeClassName
	Finalizer                   = names.Finalizer
	StateDir                    = names.StateDir
	RuncRoot                    = names.RuncRoot
	AgentPort                   = names.AgentPort
	FileRestored                = names.FileRestored
	FileColdStart               = names.FileColdStart
	FileRootfsDiff              = names.FileRootfsDiff
	FileSandbox                 = names.FileSandbox
	FileSandboxNetns            = names.FileSandboxNetns
	FileAborted                 = names.FileAborted
	FileHandOver                = names.FileHandOver
	DirImages                   = names.DirImages
)
