use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// Io defines an abstraction for input/output interactions.
pub trait Io {
    /// Print a line of normal output.
    fn print_line(&self, msg: &str);

    /// Ask for something sensitive where the terminal must not echo what is typed.
    fn prompt_password(&self, prompt: &str) -> io::Result<Zeroizing<String>>;

    /// Ask for a plain line of text echoed normally as it's typed.
    fn prompt_line(&self, prompt: &str) -> io::Result<String>;

    /// Read everything piped on standard input.
    fn read_stdin(&self) -> io::Result<String>;
}

/// Terminal input/output.
pub struct TermIo;

impl Io for TermIo {
    fn print_line(&self, msg: &str) {
        println!("{msg}");
    }

    fn prompt_password(&self, prompt: &str) -> io::Result<Zeroizing<String>> {
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }

    fn prompt_line(&self, prompt: &str) -> io::Result<String> {
        eprint!("{prompt}");
        io::stderr().flush()?;

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line.trim().to_string())
    }

    fn read_stdin(&self) -> io::Result<String> {
        let mut data = String::new();
        io::stdin().read_to_string(&mut data)?;
        Ok(data)
    }
}

#[cfg(test)]
pub mod testing {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    #[derive(Default)]
    pub struct FakeIo {
        answers: RefCell<VecDeque<String>>,
        pub printed: RefCell<Vec<String>>,
        pub prompted: RefCell<Vec<String>>,
        pub stdin: RefCell<String>,
    }

    impl FakeIo {
        pub fn with_answers<I, S>(answers: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                answers: RefCell::new(answers.into_iter().map(Into::into).collect()),
                ..Default::default()
            }
        }
    }

    impl Io for FakeIo {
        fn print_line(&self, msg: &str) {
            self.printed.borrow_mut().push(msg.to_string());
        }

        fn prompt_password(&self, prompt: &str) -> io::Result<Zeroizing<String>> {
            self.prompt_line(prompt).map(Zeroizing::new)
        }

        fn prompt_line(&self, prompt: &str) -> io::Result<String> {
            self.prompted.borrow_mut().push(prompt.to_string());
            Ok(self.answers.borrow_mut().pop_front().unwrap_or_default())
        }

        fn read_stdin(&self) -> io::Result<String> {
            Ok(self.stdin.borrow().clone())
        }
    }
}
