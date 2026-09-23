// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr test` report: what every test did, assembled as the run goes
//! and rendered three ways — the pretty console lines (printed as each
//! test finishes), a JSON document, and JUnit XML for CI annotations.

use std::fmt::Write as _;
use std::time::Duration;

use super::capture::Entry;

/// How a test ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Passed,
    Failed,
    /// `t.skip`, or not focused while a `t.only` is in the file.
    Skipped,
    Todo,
    /// Excluded by `--filter`: on the command line, not in the file.
    Filtered,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Passed => "passed",
            Status::Failed => "failed",
            Status::Skipped => "skipped",
            Status::Todo => "todo",
            Status::Filtered => "filtered",
        }
    }
}

/// One test's outcome.
#[derive(Debug, Clone)]
pub(crate) struct TestReport {
    pub(crate) name: String,
    pub(crate) status: Status,
    pub(crate) duration: Duration,
    /// `file:line` where the test was registered.
    pub(crate) site: Option<String>,
    pub(crate) error: Option<String>,
    /// Why a skipped test was skipped.
    pub(crate) reason: Option<String>,
    pub(crate) logs: Vec<Entry>,
    /// Log entries dropped past the capture bound.
    pub(crate) logs_dropped: u64,
    pub(crate) slow: bool,
}

impl TestReport {
    pub(crate) fn new(name: String, status: Status) -> Self {
        Self {
            name,
            status,
            duration: Duration::ZERO,
            site: None,
            error: None,
            reason: None,
            logs: Vec::new(),
            logs_dropped: 0,
            slow: false,
        }
    }
}

/// One file's outcomes.
#[derive(Debug, Clone)]
pub(crate) struct FileReport {
    /// The file name, as the pretty report heads its block.
    pub(crate) name: String,
    /// The path as given, for the JSON/JUnit `file`.
    pub(crate) path: String,
    pub(crate) tests: Vec<TestReport>,
    pub(crate) focused: bool,
}

/// What `--bail` left unrun.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bail {
    /// Tests of the failing file after the failure.
    pub(crate) tests: usize,
    /// Files after the failing one.
    pub(crate) files: usize,
}

/// The whole run.
#[derive(Debug, Clone, Default)]
pub(crate) struct Report {
    pub(crate) files: Vec<FileReport>,
    pub(crate) duration: Duration,
    /// Set when `--bail` stopped the run.
    pub(crate) bailed: Option<Bail>,
}

/// Totals per status.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Counts {
    pub(crate) passed: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) todo: usize,
    pub(crate) filtered: usize,
}

impl Report {
    pub(crate) fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for test in self.files.iter().flat_map(|f| &f.tests) {
            match test.status {
                Status::Passed => counts.passed += 1,
                Status::Failed => counts.failed += 1,
                Status::Skipped => counts.skipped += 1,
                Status::Todo => counts.todo += 1,
                Status::Filtered => counts.filtered += 1,
            }
        }
        counts
    }

    /// Files that still carry a `t.only`.
    pub(crate) fn focused(&self) -> Vec<&str> {
        self.files
            .iter()
            .filter(|f| f.focused)
            .map(|f| f.name.as_str())
            .collect()
    }

    /// Whether the run fails: any failure, or any `t.only` left in place
    /// (a focused file must not land in CI green).
    pub(crate) fn failed(&self) -> bool {
        self.counts().failed > 0 || !self.focused().is_empty()
    }
}

/// The pretty line(s) for one finished test, as printed under its file.
pub(crate) fn pretty_test(test: &TestReport, show_logs: bool) -> String {
    let ms = test.duration.as_millis();
    let timing = if test.slow {
        format!("({ms} ms, slow)")
    } else {
        format!("({ms} ms)")
    };
    let mut out = String::new();
    match test.status {
        Status::Passed => {
            let _ = writeln!(
                out,
                "  {}   {}  {timing}",
                nitr::diag::console_ok("ok"),
                test.name
            );
        }
        Status::Failed => {
            let _ = writeln!(
                out,
                "  {} {}  {timing}",
                nitr::diag::console_fail("FAIL"),
                test.name
            );
            if let Some(err) = &test.error {
                for line in err.lines() {
                    let _ = writeln!(out, "       {line}");
                }
            }
            if show_logs {
                out.push_str(&logs_block(test));
            }
        }
        Status::Skipped => {
            let reason = test.reason.as_deref().unwrap_or("skipped");
            let _ = writeln!(out, "  skip {} ({reason})", test.name);
        }
        Status::Todo => {
            let _ = writeln!(out, "  todo {}", test.name);
        }
        Status::Filtered => {}
    }
    out
}

/// The captured entries printed under a failure, indented; empty when
/// there are none.
pub(crate) fn logs_block(test: &TestReport) -> String {
    let mut out = String::new();
    if test.logs.is_empty() {
        return out;
    }
    let _ = writeln!(out, "       logs:");
    for entry in &test.logs {
        // A traceback spans lines; every line keeps the indent.
        for line in entry.line().lines() {
            let _ = writeln!(out, "         {line}");
        }
    }
    if test.logs_dropped > 0 {
        let _ = writeln!(
            out,
            "         ({} older entries dropped past the {}-entry capture bound)",
            test.logs_dropped,
            super::capture::MAX_ENTRIES
        );
    }
    out
}

/// The verdict at a glance: green when everything passed, the failure
/// count red when anything did not; `--bail` and a left-over `t.only`
/// each get their own line.
pub(crate) fn verdict(report: &Report) -> String {
    let counts = report.counts();
    let passed = nitr::diag::console_ok(&format!("{} passed", counts.passed));
    let failed = match counts.failed {
        0 => "0 failed".to_string(),
        n => nitr::diag::console_fail(&format!("{n} failed")),
    };
    let mut line = format!("\n{passed}, {failed}");
    if counts.skipped > 0 {
        let _ = write!(line, ", {} skipped", counts.skipped);
    }
    if counts.todo > 0 {
        let _ = write!(line, ", {} todo", counts.todo);
    }
    if counts.filtered > 0 {
        let _ = write!(line, ", {} filtered out", counts.filtered);
    }
    let _ = write!(
        line,
        " ({} file(s), {:.2} s)",
        report.files.len(),
        report.duration.as_secs_f64()
    );
    if let Some(bail) = report.bailed {
        let _ = write!(
            line,
            "\n{}",
            nitr::diag::console_fail(&format!(
                "stopped after the first failure (--bail); {} more test(s) in that file and \
                 {} file(s) not run",
                bail.tests, bail.files
            ))
        );
    }
    let focused = report.focused();
    if !focused.is_empty() {
        let _ = write!(
            line,
            "\n{}",
            nitr::diag::console_fail(&format!(
                "t.only is left in {}: the run fails until it is removed",
                focused.join(", ")
            ))
        );
    }
    line
}

/// The `--reporter json` document.
pub(crate) fn json(report: &Report) -> String {
    let counts = report.counts();
    let files: Vec<serde_json::Value> = report
        .files
        .iter()
        .map(|file| {
            let tests: Vec<serde_json::Value> = file
                .tests
                .iter()
                .map(|test| {
                    serde_json::json!({
                        "name": test.name,
                        "status": test.status.as_str(),
                        "duration_ms": test.duration.as_secs_f64() * 1000.0,
                        "slow": test.slow,
                        "site": test.site,
                        "error": test.error,
                        "reason": test.reason,
                        "logs": test.logs.iter().map(Entry::line).collect::<Vec<_>>(),
                        "logs_dropped": test.logs_dropped,
                    })
                })
                .collect();
            serde_json::json!({ "file": file.path, "focused": file.focused, "tests": tests })
        })
        .collect();
    let doc = serde_json::json!({
        "files": files,
        "summary": {
            "passed": counts.passed,
            "failed": counts.failed,
            "skipped": counts.skipped,
            "todo": counts.todo,
            "filtered": counts.filtered,
            "files": report.files.len(),
            "duration_ms": report.duration.as_secs_f64() * 1000.0,
            "bailed": report.bailed.is_some(),
            "not_run_tests": report.bailed.map_or(0, |b| b.tests),
            "not_run_files": report.bailed.map_or(0, |b| b.files),
            "focused": report.focused(),
            "ok": !report.failed(),
        },
    });
    let mut out = serde_json::to_string_pretty(&doc).unwrap_or_default();
    out.push('\n');
    out
}

/// The longest name or message the XML carries, in characters: a test
/// name built by `t.each` from request data must not become a megabyte
/// attribute.
const MAX_XML_TEXT: usize = 4096;

/// Escapes text for an XML attribute or element: the five entities, and
/// every character XML 1.0 cannot carry (controls other than tab, newline
/// and carriage return; U+FFFE/U+FFFF) is dropped — a NUL in a failure
/// message must not produce a document no parser accepts.
pub(crate) fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (count, c) in text.chars().enumerate() {
        if count >= MAX_XML_TEXT {
            out.push_str("...");
            break;
        }
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {}
            '\u{FFFE}' | '\u{FFFF}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Splits `file:line` into its parts, for the JUnit attributes.
fn site_parts(site: &str) -> (&str, Option<&str>) {
    match site.rsplit_once(':') {
        Some((file, line)) if line.bytes().all(|b| b.is_ascii_digit()) => (file, Some(line)),
        _ => (site, None),
    }
}

/// The `--reporter junit` document: one `<testsuite>` per file; GitHub
/// and GitLab annotate from it.
pub(crate) fn junit(report: &Report) -> String {
    let counts = report.counts();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"nitr test\" tests=\"{}\" failures=\"{}\" skipped=\"{}\" time=\"{:.3}\">",
        counts.passed + counts.failed + counts.skipped + counts.todo,
        counts.failed,
        counts.skipped + counts.todo,
        report.duration.as_secs_f64()
    );
    for file in &report.files {
        let tests: Vec<&TestReport> = file
            .tests
            .iter()
            .filter(|t| t.status != Status::Filtered)
            .collect();
        let failures = tests.iter().filter(|t| t.status == Status::Failed).count();
        let skipped = tests
            .iter()
            .filter(|t| matches!(t.status, Status::Skipped | Status::Todo))
            .count();
        let time: f64 = tests.iter().map(|t| t.duration.as_secs_f64()).sum();
        let _ = writeln!(
            out,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{failures}\" skipped=\"{skipped}\" time=\"{time:.3}\">",
            xml_escape(&file.name),
            tests.len()
        );
        for test in tests {
            let mut attrs = format!(
                "name=\"{}\" classname=\"{}\" time=\"{:.3}\"",
                xml_escape(&test.name),
                xml_escape(&file.name),
                test.duration.as_secs_f64()
            );
            if let Some(site) = &test.site {
                let (path, line) = site_parts(site);
                let _ = write!(attrs, " file=\"{}\"", xml_escape(path));
                if let Some(line) = line {
                    let _ = write!(attrs, " line=\"{line}\"");
                }
            }
            let _ = writeln!(out, "    <testcase {attrs}>");
            match test.status {
                Status::Failed => {
                    let error = test.error.as_deref().unwrap_or("failed");
                    let first = error.lines().next().unwrap_or("failed");
                    let _ = writeln!(
                        out,
                        "      <failure message=\"{}\">{}</failure>",
                        xml_escape(first),
                        xml_escape(error)
                    );
                }
                Status::Skipped | Status::Todo => {
                    let reason = test.reason.as_deref().unwrap_or("skipped");
                    let _ = writeln!(out, "      <skipped message=\"{}\"/>", xml_escape(reason));
                }
                Status::Passed | Status::Filtered => {}
            }
            if !test.logs.is_empty() {
                let logs: Vec<String> = test.logs.iter().map(Entry::line).collect();
                let _ = writeln!(
                    out,
                    "      <system-out>{}</system-out>",
                    xml_escape(&logs.join("\n"))
                );
            }
            let _ = writeln!(out, "    </testcase>");
        }
        let _ = writeln!(out, "  </testsuite>");
    }
    out.push_str("</testsuites>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut failed = TestReport::new("<&\"'> breaks \u{0}xml".into(), Status::Failed);
        failed.error = Some("tests/a_test.lua:3: expected 2 to equal 3\n\u{1}second line".into());
        failed.site = Some("tests/a_test.lua:2".into());
        failed.duration = Duration::from_millis(4);
        let mut skipped = TestReport::new("later".into(), Status::Todo);
        skipped.reason = Some("todo".into());
        Report {
            files: vec![FileReport {
                name: "a_test.lua".into(),
                path: "tests/a_test.lua".into(),
                tests: vec![
                    TestReport::new("works".into(), Status::Passed),
                    failed,
                    skipped,
                    TestReport::new("other".into(), Status::Filtered),
                ],
                focused: false,
            }],
            duration: Duration::from_millis(310),
            bailed: None,
        }
    }

    #[test]
    fn xml_text_is_escaped_and_stripped_of_what_xml_cannot_carry() {
        assert_eq!(xml_escape("<&\"'>"), "&lt;&amp;&quot;&apos;&gt;");
        assert_eq!(xml_escape("a\u{0}b\u{1b}c\td\u{FFFF}"), "abc\td");
        let long = "x".repeat(MAX_XML_TEXT + 10);
        assert_eq!(xml_escape(&long).chars().count(), MAX_XML_TEXT + 3);
    }

    #[test]
    fn junit_counts_and_escapes_every_test() {
        let xml = junit(&sample());
        assert!(
            xml.contains(r#"<testsuites name="nitr test" tests="3" failures="1" skipped="1""#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"name="&lt;&amp;&quot;&apos;&gt; breaks xml""#),
            "{xml}"
        );
        assert!(xml.contains(r#"file="tests/a_test.lua" line="2""#), "{xml}");
        assert!(
            xml.contains(r#"<failure message="tests/a_test.lua:3: expected 2 to equal 3">"#),
            "{xml}"
        );
        assert!(xml.contains(r#"<skipped message="todo"/>"#), "{xml}");
        assert!(
            !xml.contains("other"),
            "filtered tests are not in the document"
        );
        assert!(!xml.contains('\u{0}') && !xml.contains('\u{1}'));
    }

    #[test]
    fn the_json_report_carries_statuses_and_a_summary() {
        let doc: serde_json::Value = serde_json::from_str(&json(&sample())).expect("json");
        assert_eq!(doc["summary"]["passed"], 1);
        assert_eq!(doc["summary"]["failed"], 1);
        assert_eq!(doc["summary"]["todo"], 1);
        assert_eq!(doc["summary"]["filtered"], 1);
        assert_eq!(doc["summary"]["ok"], false);
        assert_eq!(doc["files"][0]["tests"][1]["status"], "failed");
        assert_eq!(doc["files"][0]["tests"][1]["site"], "tests/a_test.lua:2");
    }

    #[test]
    fn the_verdict_names_bail_and_a_left_over_only() {
        let mut report = sample();
        report.bailed = Some(Bail { tests: 3, files: 2 });
        report.files[0].focused = true;
        let line = verdict(&report);
        assert!(
            line.contains("1 passed, 1 failed, 1 todo, 1 filtered out (1 file(s), 0.31 s)"),
            "{line}"
        );
        assert!(
            line.contains("3 more test(s) in that file and 2 file(s) not run"),
            "{line}"
        );
        assert!(line.contains("t.only is left in a_test.lua"), "{line}");
        assert!(report.failed());
    }

    proptest::proptest! {
        /// Property: any text survives the escaper as well-formed XML
        /// character data that decodes back to the text minus exactly the
        /// characters XML 1.0 cannot carry.
        #[test]
        fn prop_junit_escaping(text in "\\PC{0,64}|[\\x00-\\x1f<>&\"']{0,32}") {
            let escaped = xml_escape(&text);
            proptest::prop_assert!(!escaped.contains('<') && !escaped.contains('>'));
            let decoded = escaped
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&");
            let expected: String = text
                .chars()
                .filter(|c| matches!(c, '\t' | '\n' | '\r') || (*c as u32 >= 0x20 && !matches!(c, '\u{FFFE}' | '\u{FFFF}')))
                .collect();
            proptest::prop_assert_eq!(decoded, expected);
        }
    }
}
