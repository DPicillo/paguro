// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Colors only on a terminal and without NO_COLOR (https://no-color.org).
var colorEnabled = isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

type style string

const (
	sBold   style = "1"
	sDim    style = "2"
	sRed    style = "31"
	sGreen  style = "32"
	sYellow style = "33"
	sBlue   style = "34"
	sCyan   style = "36"
	sHero   style = "1;97;42" // bold white on green
	sHeroW  style = "1;30;43" // black on yellow
	sHeroE  style = "1;97;41" // white on red
)

func paint(s string, styles ...style) string {
	if !colorEnabled || len(styles) == 0 {
		return s
	}
	codes := make([]string, len(styles))
	for i, st := range styles {
		codes[i] = string(st)
	}
	return "\x1b[" + strings.Join(codes, ";") + "m" + s + "\x1b[0m"
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// visibleWidth counts visible characters (excluding ANSI sequences).
func visibleWidth(s string) int { return utf8.RuneCountInString(ansiRE.ReplaceAllString(s, "")) }

func padRight(s string, w int) string {
	if d := w - visibleWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func padLeft(s string, w int) string {
	if d := w - visibleWidth(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// table renders ANSI-safe columns (text/tabwriter counts escape sequences).
// Columns whose header starts with '>' are right-aligned.
func table(header []string, rows [][]string) []string {
	right := make([]bool, len(header))
	widths := make([]int, len(header))
	for i, h := range header {
		if strings.HasPrefix(h, ">") {
			right[i], header[i] = true, h[1:]
		}
		widths[i] = visibleWidth(header[i])
	}
	for _, r := range rows {
		for i := range r {
			if i < len(widths) {
				widths[i] = max(widths[i], visibleWidth(r[i]))
			}
		}
	}
	line := func(cells []string, dim bool) string {
		parts := make([]string, len(cells))
		for i, c := range cells {
			if dim {
				c = paint(c, sDim)
			}
			if right[i] {
				parts[i] = padLeft(c, widths[i])
			} else {
				parts[i] = padRight(c, widths[i])
			}
		}
		return strings.TrimRight(strings.Join(parts, "   "), " ")
	}
	out := []string{line(header, true)}
	for _, r := range rows {
		out = append(out, line(r, false))
	}
	return out
}

// box draws a frame around the lines.
func box(title string, lines []string) []string {
	w := visibleWidth(title) + 2
	for _, l := range lines {
		w = max(w, visibleWidth(l))
	}
	out := []string{"╭─" + paint(title, sBold) + strings.Repeat("─", w-visibleWidth(title)+1) + "╮"}
	for _, l := range lines {
		out = append(out, "│ "+padRight(l, w)+" │")
	}
	return append(out, "╰"+strings.Repeat("─", w+2)+"╯")
}

// bar draws a bar from eighth blocks (value/maxValue * width).
func bar(value, maxValue float64, width int) string {
	if maxValue <= 0 || value <= 0 {
		return ""
	}
	eighths := int(value / maxValue * float64(width*8))
	if eighths == 0 {
		eighths = 1 // make it visible that it is >0
	}
	full, rest := eighths/8, eighths%8
	return strings.Repeat("█", full) + []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}[rest]
}

// Big digits (3 lines) for the freeze – the most important number.
var bigGlyphs = map[rune][3]string{
	'0': {"█▀█", "█ █", "▀▀▀"}, '1': {"▀█ ", " █ ", "▀▀▀"}, '2': {"▀▀█", "█▀▀", "▀▀▀"},
	'3': {"▀▀█", " ▀█", "▀▀▀"}, '4': {"█ █", "▀▀█", "  ▀"}, '5': {"█▀▀", "▀▀█", "▀▀▀"},
	'6': {"█▀▀", "█▀█", "▀▀▀"}, '7': {"▀▀█", "  █", "  ▀"}, '8': {"█▀█", "█▀█", "▀▀▀"},
	'9': {"█▀█", "▀▀█", "▀▀▀"}, '.': {" ", " ", "▀"}, ' ': {" ", " ", " "},
	'm': {"   ", "█▀▄▀▄", "▀ ▀ ▀"}, 's': {"   ", "█▀▀", "▄▄█"},
}

// bigText renders s (digits, '.', ' ', 'm', 's') in three lines.
func bigText(s string) [3]string {
	var rows [3]string
	for _, r := range s {
		g, ok := bigGlyphs[r]
		if !ok {
			g = [3]string{" ", " ", string(r)}
		}
		w := 0
		for _, l := range g {
			w = max(w, utf8.RuneCountInString(l))
		}
		for i := range rows {
			rows[i] += padRight(g[i], w) + " "
		}
	}
	return rows
}

func fmtMs(ms int64) string {
	switch {
	case ms <= 0:
		return "–"
	case ms < 1000:
		return fmt.Sprintf("%d ms", ms)
	case ms < 60_000:
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	default:
		return fmt.Sprintf("%dm%02ds", ms/60_000, (ms%60_000)/1000)
	}
}

func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// freezeStyles: green within budget, yellow up to twice the budget, red otherwise.
// badge is the background style, fg the matching foreground color.
func freezeStyles(ms int64, budgetMs int32) (badge, fg style) {
	b := int64(budgetMs)
	if b <= 0 {
		b = 500
	}
	switch {
	case ms <= b:
		return sHero, sGreen
	case ms <= 2*b:
		return sHeroW, sYellow
	default:
		return sHeroE, sRed
	}
}
