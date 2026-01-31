#!/usr/bin/env python3
"""
NIST SP 800-53 Rev. 5 Header Generator

Scans Rust source files for NIST control references and generates formal headers.

Usage:
    python3 scripts/generate-nist-headers.py --scan              # Scan and report
    python3 scripts/generate-nist-headers.py --generate --dry-run  # Preview headers
    python3 scripts/generate-nist-headers.py --generate --apply    # Apply headers
    python3 scripts/generate-nist-headers.py --validate          # Validate coverage
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Control family mapping
CONTROL_FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Current software version (update when releasing)
SOFTWARE_VERSION = "0.77.1"

# Validation date (today)
VALIDATION_DATE = datetime.now().strftime("%Y-%m-%d")


class NistControlScanner:
    """Scans Rust files for NIST control references."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.file_controls: Dict[Path, Set[str]] = defaultdict(set)
        self.control_locations: Dict[str, List[Tuple[Path, int]]] = defaultdict(list)

    def scan_file(self, file_path: Path) -> Set[str]:
        """Extract NIST control references from a file."""
        controls = set()

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # Pattern: [NIST:AC-3], NIST AC-3, Control AC-3, etc.
                    matches = re.findall(r'\b([A-Z]{2}-\d+)\b', line)
                    for match in matches:
                        # Verify it's a valid control family
                        family = match.split('-')[0]
                        if family in CONTROL_FAMILIES:
                            controls.add(match)
                            self.control_locations[match].append((file_path, line_num))
        except Exception as e:
            print(f"Warning: Could not scan {file_path}: {e}", file=sys.stderr)

        return controls

    def scan_directory(self, directory: Path, pattern: str = "**/*.rs") -> None:
        """Scan all Rust files in a directory."""
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                controls = self.scan_file(file_path)
                if controls:
                    self.file_controls[file_path] = controls

    def get_top_files(self, n: int = 10) -> List[Tuple[Path, Set[str]]]:
        """Get top N files by control count."""
        sorted_files = sorted(
            self.file_controls.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        return sorted_files[:n]

    def generate_report(self) -> str:
        """Generate a text report of findings."""
        lines = []
        lines.append("=" * 80)
        lines.append("NIST SP 800-53 Rev. 5 Control Coverage Report")
        lines.append("=" * 80)
        lines.append("")

        total_files = len(self.file_controls)
        total_controls = len(self.control_locations)

        lines.append(f"Files scanned: {total_files}")
        lines.append(f"Unique controls found: {total_controls}")
        lines.append("")

        # Control frequency
        lines.append("Control References by Frequency:")
        lines.append("-" * 80)
        sorted_controls = sorted(
            self.control_locations.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        for control, locations in sorted_controls[:20]:
            family = control.split('-')[0]
            family_name = CONTROL_FAMILIES.get(family, "Unknown")
            lines.append(f"  {control:8} ({family_name:30}) - {len(locations):3} references")

        lines.append("")
        lines.append("Top 10 Files by Control Count:")
        lines.append("-" * 80)

        for file_path, controls in self.get_top_files(10):
            rel_path = file_path.relative_to(self.repo_root)
            lines.append(f"  {len(controls):2} controls - {rel_path}")
            controls_str = ", ".join(sorted(controls))
            lines.append(f"      [{controls_str}]")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)


class NistHeaderGenerator:
    """Generates NIST control headers for Rust files."""

    def __init__(self, repo_root: Path, scanner: NistControlScanner):
        self.repo_root = repo_root
        self.scanner = scanner

    def calculate_relative_docs_path(self, file_path: Path) -> str:
        """Calculate relative path from file to docs/ directory."""
        try:
            rel_path = file_path.relative_to(self.repo_root)
            depth = len(rel_path.parents) - 1
            return "../" * depth + "docs/"
        except ValueError:
            return "../../../docs/"  # Fallback for crates/*/src/

    def get_control_family(self, control_id: str) -> str:
        """Get family name for a control ID."""
        family_code = control_id.split('-')[0]
        return CONTROL_FAMILIES.get(family_code, "Unknown")

    def generate_control_table_row(self, control_id: str) -> str:
        """Generate a single row for the control table."""
        family = self.get_control_family(control_id)
        return f"//! | {control_id} | {family} | Implemented | {VALIDATION_DATE} | See functions below |"

    def generate_header(self, file_path: Path, controls: Set[str]) -> str:
        """Generate NIST header for a file."""
        rel_docs = self.calculate_relative_docs_path(file_path)
        rel_file = file_path.relative_to(self.repo_root)

        # Extract unique families
        families = sorted(set(c.split('-')[0] for c in controls))

        lines = []
        lines.append("//! # NIST SP 800-53 Rev. 5 Security Controls")
        lines.append("//!")
        lines.append("//! **Control Implementation Matrix**")
        lines.append("//!")
        lines.append("//! This module implements controls documented in")
        lines.append(f"//! [{rel_docs}NIST-CONTROLS-MAPPING.md]({rel_docs}NIST-CONTROLS-MAPPING.md).")
        lines.append("//!")
        lines.append("//! | Control | Family | Status | Validated | Primary Functions |")
        lines.append("//! |---------|--------|--------|-----------|-------------------|")

        for control in sorted(controls):
            lines.append(self.generate_control_table_row(control))

        lines.append("//!")
        lines.append("//! <details>")
        lines.append("//! <summary><b>Validation Metadata (JSON)</b></summary>")
        lines.append("//!")
        lines.append("//! ```json")

        # Generate JSON metadata
        metadata = {
            "nist_framework": "NIST SP 800-53 Rev. 5",
            "software_version": SOFTWARE_VERSION,
            "last_validation": VALIDATION_DATE,
            "control_families": families,
            "total_controls": len(controls),
            "file_path": str(rel_file)
        }

        json_str = json.dumps(metadata, indent=2)
        for json_line in json_str.split('\n'):
            lines.append(f"//! {json_line}")

        lines.append("//! ```")
        lines.append("//!")
        lines.append("//! </details>")

        return "\n".join(lines)

    def preview_headers(self, top_n: int = 10) -> None:
        """Preview headers for top N files."""
        print("\n" + "=" * 80)
        print(f"Preview: Headers for Top {top_n} Files")
        print("=" * 80 + "\n")

        for file_path, controls in self.scanner.get_top_files(top_n):
            print(f"\nFile: {file_path.relative_to(self.repo_root)}")
            print(f"Controls: {len(controls)}")
            print("-" * 80)
            print(self.generate_header(file_path, controls))
            print("")

    def apply_header_to_file(self, file_path: Path, controls: Set[str]) -> bool:
        """Apply NIST header to a file. Returns True if successful."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check if file already has formal NIST header
            if "# NIST SP 800-53 Rev. 5 Security Controls" in content:
                print(f"  ⏭️  Skipping {file_path.name} (already has formal header)")
                return False

            # Find insertion point (after module docstring start)
            lines = content.split('\n')
            insert_idx = None

            # Look for //! pattern (module docstring)
            for i, line in enumerate(lines):
                if line.strip().startswith('//!') and i > 0:
                    # Find end of first paragraph or description
                    for j in range(i, min(i + 20, len(lines))):
                        if lines[j].strip() == '//!' or (
                            j > i and not lines[j].strip().startswith('//!')
                        ):
                            insert_idx = j
                            break
                    break

            if insert_idx is None:
                print(f"  ⚠️  Could not find insertion point in {file_path.name}")
                return False

            # Generate header
            header = self.generate_header(file_path, controls)

            # Insert header
            header_lines = header.split('\n')
            new_lines = lines[:insert_idx] + ['//!'] + header_lines + lines[insert_idx:]

            # Write back
            new_content = '\n'.join(new_lines)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)

            print(f"  ✅ Applied header to {file_path.name} ({len(controls)} controls)")
            return True

        except Exception as e:
            print(f"  ❌ Error applying header to {file_path}: {e}")
            return False

    def apply_headers(self, top_n: int = 10) -> int:
        """Apply headers to top N files. Returns count of files modified."""
        print(f"\n📝 Applying NIST headers to top {top_n} files...\n")

        modified = 0
        for file_path, controls in self.scanner.get_top_files(top_n):
            if self.apply_header_to_file(file_path, controls):
                modified += 1

        print(f"\n✅ Applied headers to {modified} files")
        return modified


def main():
    parser = argparse.ArgumentParser(
        description="Generate NIST SP 800-53 Rev. 5 control headers for Rust files"
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan files and generate report (no modifications)"
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate headers"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview headers without applying (use with --generate)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply generated headers to files (use with --generate)"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate that all files with NIST references have headers"
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top files to process (default: 10)"
    )

    args = parser.parse_args()

    # Find repository root
    repo_root = Path(__file__).parent.parent

    # Initialize scanner
    scanner = NistControlScanner(repo_root)

    # Scan crates directory
    crates_dir = repo_root / "crates"
    if crates_dir.exists():
        scanner.scan_directory(crates_dir)

    # Execute command
    if args.scan or (not args.generate and not args.validate):
        print(scanner.generate_report())

    if args.generate:
        generator = NistHeaderGenerator(repo_root, scanner)

        if args.dry_run or not args.apply:
            generator.preview_headers(args.top)

        if args.apply:
            modified = generator.apply_headers(args.top)
            if modified > 0:
                print(f"\n⚠️  {modified} files modified. Review changes and run tests before committing.")
                sys.exit(0)
            else:
                print("\n✅ No files needed modification")
                sys.exit(0)

    if args.validate:
        # Check if files with control references have proper headers
        print("\nValidation: Checking for NIST headers...")
        missing_headers = []

        for file_path, controls in scanner.file_controls.items():
            # Check if file has NIST header
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    if "# NIST SP 800-53 Rev. 5 Security Controls" not in content:
                        missing_headers.append((file_path, controls))
            except Exception as e:
                print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)

        if missing_headers:
            print(f"\n⚠️  {len(missing_headers)} files missing NIST headers:")
            for file_path, controls in missing_headers:
                rel_path = file_path.relative_to(repo_root)
                print(f"  - {rel_path} ({len(controls)} controls)")
        else:
            print("✅ All files with NIST references have headers!")


if __name__ == "__main__":
    main()
