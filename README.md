# qf-installer
![info](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExa2JjbmZzN3FtNDJqcWJ4ZndheW5tNWxmeGQwaHJ0YmNvN2tpOG0yaCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/0RrrWdWS9AFyu1irjQ/giphy.gif)

CLI installer app built in Rust to facilitate in delivering the correct mod and config files to Minecraft modded players. Utilizes a Python Flask API and md5 hashing. Quafuzzii is the name of the Minecraft server. FYI.

## Building
Clone this repo and run `cargo build`. Make sure to provide a server URL, and the correct secret token, or else it won't work.
