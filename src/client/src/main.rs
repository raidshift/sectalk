use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use std::io::{Write, stdout};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;
    let mut message_history = Vec::new();

    // Create a channel for communication between threads
    let (tx, rx) = mpsc::channel();

    // Spawn a thread that will periodically send messages
    thread::spawn(move || {
        let automated_messages = [
            "System: Welcome to the chat!",
            "System: This is an automated message.",
            "System: How are you doing today?",
            "System: Try typing something!",
            "System: Press ESC to exit the application.",
        ];
        let mut msg_index = 0;

        loop {
            thread::sleep(Duration::from_secs(1));
            tx.send(automated_messages[msg_index].to_string()).unwrap();
            msg_index = (msg_index + 1) % automated_messages.len();
        }
    });

    print_prompt(&input, cursor_pos);

    loop {
        // Check for automated messages
        if let Ok(message) = rx.try_recv() {
            // Save the current input state
            let current_input = input.clone();
            let current_pos = cursor_pos;

            // Clear the current line where user is typing
            execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();

            // Print the automated message
            println!("> {}", message);
            message_history.push(message);

            // Restore the input prompt
            print_prompt(&current_input, current_pos);
            input = current_input;
            cursor_pos = current_pos;

            stdout.flush().unwrap();
        }

        // Check for user input events with a short timeout
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char(c) => {
                        input.insert(cursor_pos, c);
                        cursor_pos += 1;
                    }
                    KeyCode::Left => {
                        if cursor_pos > 0 {
                            cursor_pos -= 1;
                        }
                    }
                    KeyCode::Right => {
                        if cursor_pos < input.len() {
                            cursor_pos += 1;
                        }
                    }
                    KeyCode::Backspace => {
                        if cursor_pos > 0 {
                            input.remove(cursor_pos - 1);
                            cursor_pos -= 1;
                        }
                    }
                    KeyCode::Enter => {
                        if !input.is_empty() {
                            execute!(stdout, MoveToNextLine(1), Clear(ClearType::CurrentLine), MoveToColumn(0)).unwrap();
                            let user_message = format!("> {}", input);
                            println!("{}", user_message);
                            message_history.push(user_message);
                            input.clear();
                            cursor_pos = 0;
                        }
                    }
                    KeyCode::Esc => {
                        execute!(stdout, MoveToNextLine(1), Clear(ClearType::CurrentLine), MoveToColumn(0)).unwrap();
                        println!("Exiting...");
                        execute!(stdout, MoveToNextLine(1), Clear(ClearType::CurrentLine), MoveToColumn(0)).unwrap();
                        break;
                    }
                    _ => {}
                }
                print_prompt(&input, cursor_pos);
            }
        }
    }

    disable_raw_mode().unwrap();
}

fn print_prompt(input: &str, cursor_pos: usize) {
    let mut stdout = stdout();
    execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();

    print!("> {}", input);
    // Move the cursor to the correct place (after prompt + input)
    let prompt_len = 2; // "> "
    let target_col = (prompt_len + cursor_pos) as u16;
    execute!(stdout, MoveToColumn(target_col)).unwrap();

    stdout.flush().unwrap();
}
