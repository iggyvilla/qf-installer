use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use reqwest::Response;
use bytes::Bytes;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::Write;
use std::process::exit;

use futures_util::StreamExt;
use std::cmp::min;
use std::io;
use std::path::Path;

pub fn print_logo() {
    println!("{} {} {} {} {} {} {} {} {} {}",
             "         __ _\n".bold().bright_yellow(),
             "       / _(_)\n".bold().bright_yellow(),
             "  __ _| |_ _ \n".bold().bright_yellow(),
             " / _` |  _| |".bold().bright_yellow(),  "Quafuzzii Installer v1.0\n".underline(),
             "| (_| | | | |".bold().bright_yellow(),  "Iggy Villa (C) 2025\n".dimmed(),
             " \\__, |_| |_| \n".bold().bright_yellow(),
             "    | | \n".bold().bright_yellow(),
             "    |_| \n".bold().bright_yellow()
    );
}

pub fn format_error_str(error_at: &str) -> String {
    format!(
        "{} {} `{}`. {}",
        "[ERROR]".bold().red(),
        "A critical error occurred at error code:",
        error_at.bold().red().dimmed(),
        "Please try again first, then report to Iggy."
    )
}

pub fn new_configured_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();

    pb.enable_steady_tick(Duration::from_millis(120));

    pb.set_style(
        ProgressStyle::with_template(
            format!(
                "{}{}{} {}",
                "[".bold().dimmed(),
                "{spinner:.dim}",
                "]".bold().dimmed(),
                "{msg}"
            ).as_str()
        ).unwrap()
        .tick_strings(&[
            "▹▹▹▹▹",
            "▸▹▹▹▹",
            "▹▸▹▹▹",
            "▹▹▸▹▹",
            "▹▹▹▸▹",
            "▹▹▹▹▸",
            "▪▪▪▪▪",
        ])
    );

    // to_owned() needed here because of some rust lifetime black magic
    pb.set_message(message.to_owned());

    pb
}

pub async fn download_file(res: Response, full_path: String, pb: ProgressBar, total_size: u64) -> Result<(), String> {

    let mut file = match File::create(&full_path) {
        Ok(t) => t,
        Err(e) => {
            // this happens when folder/subfolder/... doesn't exist
            // so, just create them!

            if e.kind() != io::ErrorKind::NotFound {
                println!("{}", format_error_str("download_file_perms"));
                exit(0);
            }

            let path_to_file = Path::new(full_path.as_str()).parent().unwrap();

            if let Err(_) =  create_dir_all(path_to_file) {
                println!("{}", format_error_str("create_dir_perms"));
                exit(0);
            }

            // can't error here anymore, hence the unwrap
            File::create(&full_path).unwrap()
        }
    };

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let item: Result<Bytes, reqwest::Error> = item;

        let chunk = item.expect("Error while downloading file.");

        file.write_all(&chunk).expect("Error while writing to file.");

        let new = min(downloaded + (chunk.len() as u64), total_size.clone());

        downloaded = new;

        pb.set_position(new.clone());
    }

    // pb.finish_with_message("Done!");
    pb.finish();

    Ok(())
}