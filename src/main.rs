mod qfi_utils;

use std::process::exit;
use std::time::Duration;
use std::{fs, io};
use std::env;
use std::fs::{File, metadata};
use chksum_md5 as md5;
use std::path::{MAIN_SEPARATOR_STR, Path};
use path_slash::PathExt as _;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use colored::Colorize;

use reqwest;
use serde;
use serde_json::Value;
use walkdir::WalkDir;

use urlencoding;

use qfi_utils::{format_error_str, print_logo, new_configured_spinner, download_file};


#[derive(serde::Deserialize)]
struct ApiInfoResponse {
    ver: f32,
    season: u32,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {

    // Print `qfi` logo
    print_logo();

    // used later for easy printing
    let indent = "   ";

    // Setup `reqwest` client
    let url = "<api_url>";
    let client = reqwest::Client::new();

    /* ****** CHECK IF SERVER ALIVE ****** */

    // Get server status and season information
    let pb = new_configured_spinner("Connecting to servers...");

    // Get basic info from server (and check if server is alive)
    let res = client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send().await;

    // if server is offline, Err(_) is returned
    if let Err(_) = res {
        pb.set_message("⚠️  Error connecting to Quafuzzii's CDN. Please check internet connection.");
        exit(0);
    }

    // safe to use .unwrap() here since Err(_) is handled above
    let req = res.unwrap().json::<ApiInfoResponse>().await;

    if let Ok(res) = req {
        pb.finish_with_message(
            format!(
                "{} to Quafuzzii's CDN (V{:.1}). Current supported season is {}.",
                "📦 Successfully connected".bold().green(),
                res.ver,
                res.season
            )
        );
    }

    /* ****** RETRIEVE HASH LIST ****** */

    let pb = new_configured_spinner("📋 Retrieving updated modpack file hash list...");

    let res = client
        .get(format!("{}{}", url , "/hashlist"))
        .query(&[("secret", "<secret>")])
        .timeout(Duration::from_secs(5))
        .send().await;

    if let Err(_) = res {
        pb.finish_with_message("⚠️  Error connecting to Quafuzzii's CDN. Please check internet connection.");
        exit(0);
    }

    let hashlist_txt = res
        .unwrap()
        .text()
        .await;

    if let Err(_) = hashlist_txt {
        pb.finish_with_message(
            format_error_str("hashlist_txt")
        );
    }

    let hashlist: Result<Value, serde_json::Error> = serde_json::from_str(hashlist_txt.unwrap().as_str());

    if let Err(_) = hashlist {
        pb.finish_with_message(
            format_error_str("hashlist_decode_serde")
        );
        exit(0);
    }

    // funny rust lifetime stuff
    let hashlist = hashlist.unwrap();
    let mut hashlist = hashlist.as_object().unwrap().to_owned();

    // get supported folders from API response
    // (in this case, get each folder that every path starts with)
    let mut supported_folders: Vec<String> = vec![];
    for key in hashlist.keys() {
        let root_folder = key.split("/").collect::<Vec<&str>>()[0].to_owned();

        if !supported_folders.contains(&&root_folder) {
            supported_folders.push(root_folder);
        }
    }

    pb.finish_with_message(
        format!(
            "{} Watching {} folders: {} (total of {} files).",
            "📋 Hashlist retrieved!".green().bold(),
            supported_folders.len().to_string().green(),
            supported_folders
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<&str>>()
                .join(", "),
            hashlist.keys().len().to_string().green()
        )
    );

    /* ****** COMPARING FILES WITH SERVER HASH ****** */

    let pb = new_configured_spinner("🔍 Comparing your files with the latest list...");

    // We only care about `config/`, or `mods/`, not all the folders before it

    // use when in dev environment
    // let offset_path = format!("{}{}", env::current_exe().unwrap().display().to_string(), "/src");

    // the path to get to the mods folder
    let offset_path = env::current_exe().unwrap().parent().unwrap().display().to_string();

    // TODO: this can be cleaner by having a new struct with properties path, and is_modified
    // all user files
    let mut files: Vec<String> = vec![];
    // files that are supported, but modified
    let mut files_supp_mod: Vec<String> = vec![];
    // files that aren't supported
    let mut files_not_supp: Vec<String> = vec![];

    for entry in WalkDir::new(&offset_path) {
        let dir = entry.unwrap();
        let dir = dir.path();

        if metadata(dir).unwrap().is_file() {
            let full_path = dir.to_slash().unwrap();

            // path used by the API (e.g., mods/mod.jar)
            let sliced_path = (&full_path[offset_path.len()+1..full_path.len()]).to_owned();

            // if its not in a directory, ignore
            if sliced_path.contains("/") {
                files.push(sliced_path);
            }
        }
    }

    // go through each file in files, and if the hashes are the same, remove it
    // once this process is done, we will have a list of files to download
    for path in files {
        pb.set_message(format!("{} {} {}", "🔍 Checking".dimmed(), path.dimmed().bold(), "...".dimmed()));

        // let full_path = format!("{}{}{}", offset_path, "/", path);

        let off_path = Path::new(&offset_path);
        let full_path = off_path.join(&path);

        let file = match File::open(&full_path) {
            Err(why) => panic!("couldn't open {}: {}", full_path.display(), why),
            Ok(file) => file,
        };

        let md5_hash = md5::chksum(file).unwrap().to_hex_lowercase();

        match hashlist.get(path.as_str()) {
            Some(T) => {
                // server has the file's hash in stock
                // if the hash is the same, ignore
                let server_hash = T.to_string();

                // server hash includes quotation marks around key, so
                // .trim_matches() removes it
                if !(md5_hash == server_hash.trim_matches('\"')) {
                    // if file is supported but hash is different
                    files_supp_mod.push(path.to_owned());
                }
            },
            _ => {
                // file is not supported, only warn user
                files_not_supp.push(path.to_owned());
            }
        }

        hashlist.remove(&path);
    }

    pb.finish_with_message(
        format!(
            "{} Found {} outdated/modified file(s), {} unsupported, and {} missing.",
            "🔍 Finished scan!".bold().green(),
            files_supp_mod.len().to_string().green(),
            files_not_supp.len().to_string().yellow(),
            hashlist.keys().collect::<Vec<&String>>().len().to_string().dimmed().bold()
        )
    );

    /* ****** INFORM USER OF FILE MISMATCHES ****** */

    if !files_not_supp.is_empty() {
        println!("\n");
        // warn unsupported files
        println!(
            "{}{}\n{}consider removing them if any crashing occurs:",
            indent,
            "These files are not supported!".yellow().bold(),
            indent
        );
        for file in files_not_supp {
            println!("{}  {} {}", indent, "-->".bold().dimmed(), file.italic())
        }
    } else {
        println!("\n\n{}{}",
                 indent,
                 "No unsupported files!".bold().green());
    }

    println!();

    // inform modified files
    if !files_supp_mod.is_empty() {
        println!(
            "{}{}\n{}and will be disabled (with your permission) and updated:",
            indent,
            "These files are outdated/modified".yellow().bold(),
            indent
        );
        for (idx, file) in files_supp_mod.iter().enumerate() {
            println!("{}  {} {}", indent,
                     format!("({})", idx).bold().dimmed(), file.italic())
        }
    } else {
        println!("{}{}",
                 indent,
                 "No modified files!".bold().green());
    }

    println!();

    // inform missing files
    if !hashlist.is_empty() {
        println!(
            "{}{}\n{}and will be downloaded from the CDN:",
            indent,
            "These files are missing".red().bold(),
            indent
        );
        for (file, _) in &hashlist {
            println!(
                "{}  {} {}",
                indent,
                "-->".bold().dimmed(),
                file.italic()
            );
        }
    } else {
        println!("{}{}", indent, "No missing files!".bold().green());
    }

    println!();

    /* ****** PROCESS FILE REMOVAL WHITELIST ****** */

    if !files_supp_mod.is_empty() {

        println!("{} that will {} {}", "Enter index of files".bold(), "NOT be removed".bold(), "(ex. 1,3,4 OR enter for none): ");

        'a: loop {
            let mut buf = String::new();
            io::stdin()
                .read_line(&mut buf)
                .expect("Error reading terminal input.");

            if buf.trim() != "" {
                let mut to_remove: Vec<usize> = vec![];

                for entry in buf.trim().split(",") {
                    let idx = match entry.trim().parse::<usize>() {
                        Ok(T) => T,
                        _ => {
                            println!("{} {}{}",
                                     "Invalid (+) integer:".italic().dimmed(),
                                     entry.to_string().italic().dimmed().bold(),
                                     ". Try again.".italic().dimmed()
                            );
                            continue 'a;
                        }
                    };

                    to_remove.push(idx);
                }

                for idx in to_remove {
                    if idx < files_supp_mod.len() {
                        files_supp_mod.remove(idx);
                    } else {
                        println!(
                            "{} {}{}",
                             "Invalid index:".italic().dimmed(),
                             idx.to_string().italic().dimmed().bold(),
                             ". Try again.".italic().dimmed()
                        );
                        continue 'a;
                    }
                }

                println!("{} items at indices.", "Successfully whitelisted".green().bold());
                println!();

                break 'a;
            } else {
                break 'a;
            }
        }
    }

    /* ****** DISABLE MODIFIED FILES (NOT DELETE!) ****** */

    // hide modified files
    let pb = new_configured_spinner("⚙️  Disabling modified/outdated files...");

    for fp in files_supp_mod.iter() {

        let fp = offset_path.clone() + "/" + fp;
        let fp = fp.as_str();

        if let Err(E) = fs::rename(fp, format!("{}{}", fp, ".disabled").as_str()) {
            println!("Error modifying file {}: {}. Please try again/run as administrator.", fp, E);
            exit(0);
        }
    }

    pb.finish_with_message(
        format!(
            "{} {} {}",
            "⚙️  Finished disabling".bold().green(),
            files_supp_mod.len(),
            "files."
        )
    );

    /* ****** DOWNLOAD NEEDED FILES ****** */

    // files to download
    let mut files_dl: Vec<String> = vec![];

    files_dl.extend(files_supp_mod);
    files_dl.extend(hashlist.keys().map(|x| x.to_owned()).collect::<Vec<String>>());

    if !files_dl.is_empty() {
        println!("\n");
        println!("{}{} {}\n", indent, "📥 Downloading".bold().green(), "missing files...".bold());
    }

    let m = MultiProgress::new();

    let mut tasks = Vec::with_capacity(files_dl.len());

    for file in files_dl {
        let url = format!("{}{}{}", url, "/getfile/", urlencoding::encode(file.as_str()));

        let full_path = format!("{}{}{}", offset_path, "/", file);

        let res = match client
            .get(url)
            .query(&[("secret", "<secret>")])
            .send()
            .await {

            Ok(T) => T,
            Err(_) => {
                println!("{}", format_error_str("download_file_get"));
                exit(0);
            }
        };

        let total_size = res.content_length().unwrap();

        let pb = m.add(ProgressBar::new(total_size));
        pb.set_style(
            ProgressStyle::with_template(
                format!(
                    "{}{}{}{}",
                    "[".dimmed().bold(),
                    "{spinner:.dim.bold}",
                    "] ".dimmed().bold(),
                    "{wide_msg:.italic} {bytes}/{total_bytes} ({elapsed:.dim}) ").as_str()
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

        pb.set_message(file);

        // do downloads asynchronously
        tasks.push(
        tokio::spawn( async move {
                download_file(
                    res,
                    full_path,
                    pb,
                    total_size.clone(),
                ).await
            })
        );
    }

    let mut outputs = Vec::with_capacity(tasks.len());

    for task in tasks {
        outputs.push(task
            .await
            .unwrap()
        );
    }

    println!("\n\n{} {} Press enter to exit...", indent, "✅ Installer finished!".bold().green());

    let mut buf: String = String::new();
    io::stdin()
        .read_line(&mut buf)
        .expect("Error reading line.");

}
