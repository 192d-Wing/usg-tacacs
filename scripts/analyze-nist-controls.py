#!/usr/bin/env python3
"""
Analyze NIST SP 800-53 control references in usg-tacacs source code.

This script:
1. Scans Rust source files for NIST control references
2. Extracts control IDs, contexts, and locations
3. Generates a report of control usage per file
4. Identifies files that need formal headers
"""

import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import json

# NIST control ID pattern (e.g., AC-3, AU-12, IA-2, SC-23)
CONTROL_PATTERN = re.compile(r'\b([A-Z]{2})-([0-9]+)\b')

# Inline NIST marker pattern (e.g., // [NIST:AC-3], // NIST AC-10:)
INLINE_MARKER_PATTERN = re.compile(r'//.*?\[?NIST:?\s*([A-Z]{2}-[0-9]+)\]?')

# Function-level NIST table pattern
FUNCTION_TABLE_PATTERN = re.compile(
    r'///\s*#\s*NIST.*?Controls?.*?\n(.*?)(?=\n\s*(?:pub |fn |async |$))',
    re.DOTALL | re.IGNORECASE
)

# Module-level NIST section pattern
MODULE_SECTION_PATTERN = re.compile(
    r'//!.*?#\s*NIST.*?Controls?.*?\n(.*?)(?=\n(?://!|\n|use |pub ))',
    re.DOTALL | re.IGNORECASE
)


class ControlReference:
    """Represents a single NIST control reference in code."""

    def __init__(self, control_id: str, file_path: str, line_num: int, context: str):
        self.control_id = control_id
        self.file_path = file_path
        self.line_num = line_num
        self.context = context
        self.ref_type = self._classify_context(context)

    def _classify_context(self, context: str) -> str:
        """Classify the type of reference based on context."""
        if '//!' in context:
            return 'module_doc'
        elif '///' in context:
            return 'function_doc'
        elif '// [NIST:' in context or '// NIST' in context:
            return 'inline_marker'
        else:
            return 'other'

    def __repr__(self):
        return f"{self.control_id}@{self.file_path}:{self.line_num} ({self.ref_type})"


class FileAnalysis:
    """Analysis results for a single file."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.controls: Set[str] = set()
        self.references: List[ControlReference] = []
        self.has_module_header = False
        self.has_function_tables = False
        self.has_inline_markers = False
        self.line_count = 0

    def add_reference(self, ref: ControlReference):
        """Add a control reference to this file."""
        self.references.append(ref)
        self.controls.add(ref.control_id)

        if ref.ref_type == 'module_doc':
            self.has_module_header = True
        elif ref.ref_type == 'function_doc':
            self.has_function_tables = True
        elif ref.ref_type == 'inline_marker':
            self.has_inline_markers = True

    def control_count(self) -> int:
        """Number of unique controls referenced."""
        return len(self.controls)

    def needs_formal_header(self) -> bool:
        """Check if this file needs a formal NIST header."""
        # Needs header if it has controls but no formal module header
        return self.control_count() > 0 and not self.has_module_header

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export."""
        return {
            'file_path': self.file_path,
            'control_count': self.control_count(),
            'controls': sorted(list(self.controls)),
            'has_module_header': self.has_module_header,
            'has_function_tables': self.has_function_tables,
            'has_inline_markers': self.has_inline_markers,
            'needs_formal_header': self.needs_formal_header(),
            'line_count': self.line_count,
            'reference_count': len(self.references)
        }


def find_rust_files(root_dir: Path) -> List[Path]:
    """Find all Rust source files in the project."""
    rust_files = []

    # Search in crates/ and src/
    for pattern in ['crates/**/*.rs', 'src/**/*.rs']:
        rust_files.extend(root_dir.glob(pattern))

    return sorted(rust_files)


def analyze_file(file_path: Path, root_dir: Path) -> FileAnalysis:
    """Analyze a single Rust file for NIST control references."""
    rel_path = str(file_path.relative_to(root_dir))
    analysis = FileAnalysis(rel_path)

    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.split('\n')
        analysis.line_count = len(lines)

        # Search line by line for control references
        for line_num, line in enumerate(lines, start=1):
            # Find all control IDs in this line
            for match in CONTROL_PATTERN.finditer(line):
                control_id = match.group(0)

                # Get context (surrounding lines for better classification)
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[start:end])

                ref = ControlReference(control_id, rel_path, line_num, context)
                analysis.add_reference(ref)

    except Exception as e:
        print(f"Error analyzing {rel_path}: {e}", file=sys.stderr)

    return analysis


def generate_report(analyses: List[FileAnalysis]) -> str:
    """Generate a human-readable report."""
    lines = []
    lines.append("# NIST Control Usage Analysis")
    lines.append("")
    lines.append(f"**Generated:** {Path.cwd()}")
    lines.append(f"**Files analyzed:** {len(analyses)}")
    lines.append("")

    # Summary statistics
    total_controls = set()
    files_with_controls = [a for a in analyses if a.control_count() > 0]
    files_needing_headers = [a for a in analyses if a.needs_formal_header()]

    for analysis in files_with_controls:
        total_controls.update(analysis.controls)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total unique controls:** {len(total_controls)}")
    lines.append(f"- **Files with controls:** {len(files_with_controls)}")
    lines.append(f"- **Files with module headers:** {sum(1 for a in files_with_controls if a.has_module_header)}")
    lines.append(f"- **Files needing headers:** {len(files_needing_headers)}")
    lines.append("")

    # Top files by control count
    lines.append("## Top Files by Control Count")
    lines.append("")
    lines.append("| File | Controls | Has Header | Refs | Lines |")
    lines.append("|------|----------|------------|------|-------|")

    top_files = sorted(files_with_controls, key=lambda a: a.control_count(), reverse=True)[:15]
    for analysis in top_files:
        header_status = "✅" if analysis.has_module_header else "❌"
        lines.append(
            f"| {analysis.file_path} | {analysis.control_count()} | {header_status} | "
            f"{len(analysis.references)} | {analysis.line_count} |"
        )

    lines.append("")

    # Files needing formal headers (priority list)
    if files_needing_headers:
        lines.append("## Files Needing Formal Headers (Priority Order)")
        lines.append("")
        lines.append("| Priority | File | Controls | Control IDs |")
        lines.append("|----------|------|----------|-------------|")

        sorted_needing = sorted(files_needing_headers, key=lambda a: a.control_count(), reverse=True)
        for idx, analysis in enumerate(sorted_needing[:20], start=1):
            control_list = ', '.join(sorted(list(analysis.controls))[:5])
            if len(analysis.controls) > 5:
                control_list += f", ... (+{len(analysis.controls) - 5} more)"
            lines.append(f"| {idx} | {analysis.file_path} | {analysis.control_count()} | {control_list} |")

        lines.append("")

    # Control family distribution
    lines.append("## Control Family Distribution")
    lines.append("")

    family_counts = defaultdict(int)
    for control_id in total_controls:
        family = control_id.split('-')[0]
        family_counts[family] += 1

    lines.append("| Family | Count |")
    lines.append("|--------|-------|")
    for family in sorted(family_counts.keys()):
        lines.append(f"| {family} | {family_counts[family]} |")

    lines.append("")

    return '\n'.join(lines)


def generate_json_report(analyses: List[FileAnalysis]) -> str:
    """Generate a JSON report for machine processing."""
    files_with_controls = [a for a in analyses if a.control_count() > 0]

    # Collect all unique controls
    all_controls = set()
    for analysis in files_with_controls:
        all_controls.update(analysis.controls)

    # Build control-to-files mapping
    control_to_files = defaultdict(list)
    for analysis in files_with_controls:
        for control_id in analysis.controls:
            control_to_files[control_id].append(analysis.file_path)

    report = {
        'summary': {
            'total_files_analyzed': len(analyses),
            'files_with_controls': len(files_with_controls),
            'unique_controls': len(all_controls),
            'files_needing_headers': sum(1 for a in analyses if a.needs_formal_header())
        },
        'files': [a.to_dict() for a in files_with_controls],
        'controls': {
            control_id: {
                'file_count': len(files),
                'files': sorted(files)
            }
            for control_id, files in sorted(control_to_files.items())
        }
    }

    return json.dumps(report, indent=2)


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        root_dir = Path(sys.argv[1])
    else:
        # Assume we're in the repo root or scripts directory
        root_dir = Path.cwd()
        if root_dir.name == 'scripts':
            root_dir = root_dir.parent

    if not root_dir.exists():
        print(f"Error: Directory {root_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing NIST controls in: {root_dir}", file=sys.stderr)

    # Find and analyze all Rust files
    rust_files = find_rust_files(root_dir)
    print(f"Found {len(rust_files)} Rust files", file=sys.stderr)

    analyses = []
    for rust_file in rust_files:
        analysis = analyze_file(rust_file, root_dir)
        analyses.append(analysis)

    # Generate reports
    markdown_report = generate_report(analyses)
    json_report = generate_json_report(analyses)

    # Write markdown report
    output_md = root_dir / 'docs' / 'nist-control-analysis.md'
    output_md.write_text(markdown_report, encoding='utf-8')
    print(f"Markdown report written to: {output_md}", file=sys.stderr)

    # Write JSON report
    output_json = root_dir / 'docs' / 'nist-control-analysis.json'
    output_json.write_text(json_report, encoding='utf-8')
    print(f"JSON report written to: {output_json}", file=sys.stderr)

    # Print summary to stdout
    print("")
    print("Analysis complete!")
    print(f"  - Files with controls: {len([a for a in analyses if a.control_count() > 0])}")
    print(f"  - Files needing headers: {len([a for a in analyses if a.needs_formal_header()])}")
    print(f"  - Unique controls found: {len(set(c for a in analyses for c in a.controls))}")


if __name__ == '__main__':
    main()
