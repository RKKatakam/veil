//! The hunk picker of `vl split -i` and `vl squash -i`: one question per
//! hunk, answered with a line (`y`, `n`, `s`, `q`, `a`, `d`, `?`), as
//! `git add -p` asks. It reads answers from standard input whether or not it
//! is a terminal, so a script (or a test) can pipe them in, one per line;
//! the hunks and questions go to standard error, which keeps standard
//! output for the result (`--json`).
//!
//! Every unit of the change is asked about in `vl diff` order. A file whose
//! hunks cannot be chosen (binary, conflicted, sealed for a scope this
//! reader cannot read, …: `selection::Whole`) is asked about once, whole.
//! The answers running out before every question is answered is an error
//! (nothing is changed): a script that means "leave the rest" says `q`.

use std::io::{BufRead, Write};

use anyhow::{bail, Result};
use veil_core::{
    hunks::{block_view, Hunk, Line, LineKind},
    selection::{Content, Pick, Selection, Unit},
    VPath,
};

use crate::render::{safe, safe_content_line};

/// What the questions say the chosen part becomes.
#[derive(Clone, Copy, Debug)]
pub enum Purpose {
    /// `vl split -i`: the first change.
    Split,
    /// `vl squash -i`: moved to the destination.
    Squash,
}

impl Purpose {
    fn verb(self, what: &str) -> String {
        match self {
            Purpose::Split => format!("Put {what} in the first change"),
            Purpose::Squash => format!("Move {what} to the destination"),
        }
    }
}

pub struct Picker<R, W> {
    input: R,
    out: W,
    color: bool,
    purpose: Purpose,
    echo: bool,
}

/// How a question was answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
    Split,
    /// This and every later question of this file: yes.
    All,
    /// This and every later question of this file: no.
    Done,
    /// No to this and to everything after it.
    Quit,
}

/// What happens after a unit.
enum Flow {
    Next,
    Quit,
}

const HELP: &str = "\
y - yes, take this hunk
n - no, leave this hunk
s - split this hunk into smaller ones (where unchanged lines separate its edits)
a - take this hunk and every later hunk of this file
d - leave this hunk and every later hunk of this file
q - quit: leave this hunk and everything after it (what was taken so far stays taken)
? - this help";

impl<R: BufRead, W: Write> Picker<R, W> {
    pub fn new(input: R, out: W, color: bool, purpose: Purpose) -> Self {
        Picker { input, out, color, purpose, echo: false }
    }

    /// Repeat each answer after its question (answers piped in are not
    /// echoed by a terminal, and the transcript would run together).
    pub fn echo(mut self, on: bool) -> Self {
        self.echo = on;
        self
    }

    fn paint(&self, s: &str, code: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    /// Ask about every unit at or below one of `only` (every unit if
    /// empty); the units not asked about are left.
    pub fn run(&mut self, units: &[Unit], only: &[VPath]) -> Result<Selection> {
        let mut sel = Selection::new();
        let asked: Vec<&Unit> = units.iter().filter(|u| only.is_empty() || only.iter().any(|p| u.path.starts_with(p))).collect();
        if asked.is_empty() {
            bail!("there are no changes to choose from");
        }
        for u in asked {
            let mut pick = Pick::default();
            let flow = self.unit(u, &mut pick)?;
            if !u.is_none(&pick) {
                sel.insert(u.path.clone(), pick);
            }
            if let Flow::Quit = flow {
                break;
            }
        }
        Ok(sel)
    }

    fn header(&mut self, u: &Unit) -> Result<()> {
        let what = match u.status() {
            'A' => "added",
            'D' => "deleted",
            _ => "modified",
        };
        let line = format!("{} {} ({what})", self.paint("diff", "1"), safe(u.path.as_str()));
        writeln!(self.out, "{line}")?;
        Ok(())
    }

    fn unit(&mut self, u: &Unit, pick: &mut Pick) -> Result<Flow> {
        self.header(u)?;
        let t = match &u.content {
            Content::Text(t) => t,
            Content::Whole(w) => {
                let note = format!("  (whole file: {})", safe(&w.why()));
                writeln!(self.out, "{}", self.paint(&note, "2"))?;
                return self.whole(u, pick);
            }
            Content::Pending => {
                writeln!(self.out, "{}", self.paint("  (whole file)", "2"))?;
                return self.whole(u, pick);
            }
        };
        let total = t.diff.hunks.len() + usize::from(t.mode.is_some());
        let mut n = 0;
        // Once `a` or `d` is answered, the rest of the file follows it.
        let mut rest: Option<bool> = None;
        if let Some((old, new)) = t.mode {
            n += 1;
            let mode = |x: bool| if x { "100755" } else { "100644" };
            writeln!(self.out, "{}", self.paint(&format!("mode change {} → {}", mode(old), mode(new)), "33"))?;
            match self.ask(&format!("({n}/{total}) {} [y,n,q,a,d,?]? ", self.purpose.verb("this mode change")), false)? {
                Answer::Yes => pick.mode = true,
                Answer::All => {
                    pick.mode = true;
                    rest = Some(true);
                }
                Answer::Done => rest = Some(false),
                Answer::Quit => return Ok(Flow::Quit),
                Answer::No | Answer::Split => {}
            }
        }
        for (h, hunk) in t.diff.hunks.iter().enumerate() {
            n += 1;
            if let Some(take) = rest {
                if take {
                    pick.blocks.extend((0..hunk.blocks.len()).map(|b| (h, b)));
                }
                continue;
            }
            self.show_hunk(hunk)?;
            let splittable = hunk.blocks.len() > 1;
            let keys = if splittable { "y,n,q,a,d,s,?" } else { "y,n,q,a,d,?" };
            let answer = self.ask(&format!("({n}/{total}) {} [{keys}]? ", self.purpose.verb("this hunk")), splittable)?;
            match answer {
                Answer::Yes => pick.blocks.extend((0..hunk.blocks.len()).map(|b| (h, b))),
                Answer::No => {}
                Answer::All => {
                    pick.blocks.extend((0..hunk.blocks.len()).map(|b| (h, b)));
                    rest = Some(true);
                }
                Answer::Done => rest = Some(false),
                Answer::Quit => return Ok(Flow::Quit),
                Answer::Split => {
                    let k = hunk.blocks.len();
                    writeln!(self.out, "{}", self.paint(&format!("Split into {k} hunks."), "2"))?;
                    for b in 0..k {
                        if let Some(take) = rest {
                            if take {
                                pick.blocks.insert((h, b));
                            }
                            continue;
                        }
                        let (head, lines) = block_view(hunk, b);
                        self.show_lines(&head, lines)?;
                        let q = format!("({n}.{}/{total}) {} [y,n,q,a,d,?]? ", b + 1, self.purpose.verb("this hunk"));
                        match self.ask(&q, false)? {
                            Answer::Yes => {
                                pick.blocks.insert((h, b));
                            }
                            Answer::All => {
                                pick.blocks.insert((h, b));
                                rest = Some(true);
                            }
                            Answer::Done => rest = Some(false),
                            Answer::Quit => return Ok(Flow::Quit),
                            Answer::No | Answer::Split => {}
                        }
                    }
                }
            }
        }
        Ok(Flow::Next)
    }

    fn whole(&mut self, _u: &Unit, pick: &mut Pick) -> Result<Flow> {
        match self.ask(&format!("{} [y,n,q,?]? ", self.purpose.verb("this file")), false)? {
            Answer::Yes | Answer::All => pick.whole = true,
            Answer::Quit => return Ok(Flow::Quit),
            Answer::No | Answer::Done | Answer::Split => {}
        }
        Ok(Flow::Next)
    }

    fn show_hunk(&mut self, h: &Hunk) -> Result<()> {
        let head = format!("@@ -{},{} +{},{} @@", h.old_start, h.old_lines, h.new_start, h.new_lines);
        self.show_lines(&head, &h.lines)
    }

    fn show_lines(&mut self, head: &str, lines: &[Line]) -> Result<()> {
        writeln!(self.out, "{}", self.paint(head, "36"))?;
        for l in lines {
            let text = l.text.strip_suffix('\n').unwrap_or(&l.text);
            // File content comes from the repository (possibly a remote).
            let shown = format!("{}{}", l.kind.prefix(), safe_content_line(text));
            let shown = match l.kind {
                LineKind::Added => self.paint(&shown, "32"),
                LineKind::Removed => self.paint(&shown, "31"),
                LineKind::Context => shown,
            };
            writeln!(self.out, "{shown}")?;
            if !l.text.ends_with('\n') {
                writeln!(self.out, "\\ No newline at end of file")?;
            }
        }
        Ok(())
    }

    /// Ask until a known answer comes.
    fn ask(&mut self, question: &str, can_split: bool) -> Result<Answer> {
        loop {
            write!(self.out, "{}", self.paint(question, "34;1"))?;
            self.out.flush()?;
            let mut line = String::new();
            if self.input.read_line(&mut line)? == 0 {
                writeln!(self.out)?;
                bail!("the answers ended before every hunk was decided, so nothing was changed (answer `q` to leave the rest)");
            }
            let a = line.trim();
            if self.echo {
                writeln!(self.out, "{}", safe(a))?;
            }
            let answer = match a {
                "y" | "Y" | "yes" => Answer::Yes,
                "n" | "N" | "no" => Answer::No,
                "a" => Answer::All,
                "d" => Answer::Done,
                "q" => Answer::Quit,
                "s" if can_split => Answer::Split,
                "s" => {
                    writeln!(self.out, "{}", self.paint("This hunk cannot be split further.", "31"))?;
                    continue;
                }
                "?" | "h" | "help" => {
                    writeln!(self.out, "{HELP}")?;
                    continue;
                }
                _ => {
                    writeln!(self.out, "{}", self.paint(&format!("Unknown answer {}: ? shows the choices.", safe(a)), "31"))?;
                    continue;
                }
            };
            return Ok(answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use veil_core::{
        hunks::diff_text,
        selection::{TextUnit, Whole},
        tree::TreeChange,
    };

    use super::*;

    fn text_unit(path: &str, old: &str, new: &str, mode: Option<(bool, bool)>) -> Unit {
        let p = VPath::new(path).unwrap();
        Unit {
            path: p.clone(),
            changes: vec![TreeChange { path: p, old: None, new: None }],
            content: Content::Text(TextUnit { old: old.into(), new: new.into(), diff: diff_text(old, new), mode }),
        }
    }

    fn run(units: &[Unit], answers: &str) -> Result<(Selection, String)> {
        let mut out = Vec::new();
        let sel = Picker::new(answers.as_bytes(), &mut out, false, Purpose::Split).run(units, &[])?;
        Ok((sel, String::from_utf8(out).unwrap()))
    }

    const OLD: &str = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n";
    const NEW: &str = "1\nTWO\n3\n4\n5\nSIX\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\nextra\n";

    #[test]
    fn answers_choose_hunks_and_blocks() {
        let units = vec![text_unit("a.txt", OLD, NEW, Some((false, true)))];
        // mode: n; hunk 1: split → block 1 yes, block 2 no; hunk 2: yes.
        let (sel, out) = run(&units, "n\ns\ny\nn\ny\n").unwrap();
        let pick = &sel[&VPath::new("a.txt").unwrap()];
        assert!(!pick.mode);
        assert_eq!(pick.blocks, BTreeSet::from([(0, 0), (1, 0)]));
        assert!(out.contains("mode change 100644 → 100755"));
        assert!(out.contains("Split into 2 hunks."));
        assert!(out.contains("(2.1/3) Put this hunk in the first change"));
    }

    #[test]
    fn a_d_q_and_help() {
        let units = vec![text_unit("a.txt", OLD, NEW, None), text_unit("b.txt", "x\n", "y\n", None)];
        let (sel, _) = run(&units, "a\nn\n").unwrap();
        assert_eq!(sel[&VPath::new("a.txt").unwrap()].blocks.len(), 3);
        assert!(!sel.contains_key(&VPath::new("b.txt").unwrap()));
        let (sel, out) = run(&units, "?\nwhat\ny\nq\n").unwrap();
        assert!(out.contains("s - split this hunk"));
        assert!(out.contains("Unknown answer what"));
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[&VPath::new("a.txt").unwrap()].blocks, BTreeSet::from([(0, 0), (0, 1)]));
        let (sel, _) = run(&units, "d\ny\n").unwrap();
        assert_eq!(sel.keys().map(|p| p.as_str()).collect::<Vec<_>>(), ["b.txt"]);
    }

    #[test]
    fn running_out_of_answers_is_an_error() {
        let units = vec![text_unit("a.txt", OLD, NEW, None)];
        assert!(run(&units, "y\n").unwrap_err().to_string().contains("nothing was changed"));
        assert!(run(&units, "").is_err());
    }

    #[test]
    fn whole_files_are_asked_once_and_content_is_escaped() {
        let p = VPath::new("bin").unwrap();
        let units = vec![
            Unit {
                path: p.clone(),
                changes: vec![TreeChange { path: p, old: None, new: None }],
                content: Content::Whole(Whole::Binary),
            },
            text_unit("e.txt", "a\n", "\x1b]0;pwned\x07\n", None),
        ];
        let (sel, out) = run(&units, "y\nn\n").unwrap();
        assert!(sel[&VPath::new("bin").unwrap()].whole);
        assert!(out.contains("whole file: binary"));
        assert!(!out.contains('\x1b'), "escape sequences in content never reach the terminal: {out:?}");
        // `s` on a hunk of one block is refused, not taken as an answer.
        let (_, out) = run(&units[1..], "s\nn\n").unwrap();
        assert!(out.contains("cannot be split further"));
    }
}
