// Rust guideline compliant 2026-02-21

use std::env;
use std::ffi::OsStr;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use tempfile::TempDir;

pub struct TestCluster {
    temp_dir: TempDir,
    port: u16,
    pg_ctl: PathBuf,
}

impl TestCluster {
    pub fn start_without_migrations() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().join("data");
        let socket_dir = temp_dir.path().join("socket");
        std::fs::create_dir_all(&socket_dir).unwrap();

        let initdb = find_pg_binary("initdb");
        let pg_ctl = find_pg_binary("pg_ctl");
        let port = reserve_port();

        run_command(
            Command::new(&initdb)
                .arg("-D")
                .arg(&data_dir)
                .arg("--username=postgres")
                .arg("--auth=trust")
                .arg("--no-locale"),
        );
        write_tls_assets(&data_dir);
        require_tls_hba(&data_dir);
        run_command(
            Command::new(&pg_ctl)
                .arg("-D")
                .arg(&data_dir)
                .arg("-o")
                .arg(format!(
                    "-F -p {port} -k {} -c ssl=on",
                    socket_dir.display()
                ))
                .arg("start"),
        );
        wait_for_postgres(port);

        Self {
            temp_dir,
            port,
            pg_ctl,
        }
    }

    pub async fn tls_pool(&self, max_connections: u32) -> PgPool {
        // Gate F: every test pool proves the server rejects cleartext first.
        assert_cleartext_rejected(self.connect_options(PgSslMode::Disable)).await;

        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(self.connect_options(PgSslMode::Require))
            .await
            .unwrap()
    }

    fn connect_options(&self, ssl_mode: PgSslMode) -> PgConnectOptions {
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(self.port)
            .username("postgres")
            .database("postgres")
            .ssl_mode(ssl_mode)
    }
}

async fn assert_cleartext_rejected(connect_options: PgConnectOptions) {
    let result = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options)
        .await;

    assert!(
        result.is_err(),
        "TLS-required Postgres unexpectedly accepted cleartext"
    );
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        let data_dir = self.temp_dir.path().join("data");
        let _ = Command::new(&self.pg_ctl)
            .arg("-D")
            .arg(&data_dir)
            .arg("-m")
            .arg("immediate")
            .arg("stop")
            .status();
    }
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_postgres(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "temporary Postgres cluster did not start listening on port {port}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn find_pg_binary(name: &str) -> PathBuf {
    for candidate in command_search_paths(name) {
        if candidate.exists() {
            return candidate;
        }
    }

    panic!("failed to locate required Postgres binary `{name}`");
}

fn find_openssl_binary() -> PathBuf {
    for candidate in openssl_search_paths() {
        if candidate.exists() {
            return candidate;
        }
    }

    panic!("failed to locate required OpenSSL binary `openssl`");
}

fn command_search_paths(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            candidates.push(dir.join(name));
        }
    }

    candidates.push(Path::new("/opt/homebrew/opt/postgresql@16/bin").join(name));
    candidates.push(Path::new("/usr/local/opt/postgresql@16/bin").join(name));
    candidates
}

fn openssl_search_paths() -> Vec<PathBuf> {
    let mut candidates = command_search_paths("openssl");
    candidates.push(Path::new("/opt/homebrew/bin/openssl").to_path_buf());
    candidates.push(Path::new("/usr/bin/openssl").to_path_buf());
    candidates
}

fn write_tls_assets(data_dir: &Path) {
    let openssl = find_openssl_binary();
    run_command(
        Command::new(openssl)
            .arg("req")
            .arg("-new")
            .arg("-x509")
            .arg("-days")
            .arg("3650")
            .arg("-nodes")
            .arg("-subj")
            .arg("/CN=localhost")
            .arg("-keyout")
            .arg(data_dir.join("server.key"))
            .arg("-out")
            .arg(data_dir.join("server.crt")),
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            data_dir.join("server.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

fn require_tls_hba(data_dir: &Path) {
    std::fs::write(
        data_dir.join("pg_hba.conf"),
        "\
local all all trust
hostssl all all 127.0.0.1/32 trust
hostssl all all ::1/128 trust
",
    )
    .unwrap();
}

fn run_command(command: &mut Command) {
    let rendered = render_command(command);
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let status = command.status().unwrap();
    assert!(
        status.success(),
        "command `{rendered}` failed with status {status}",
    );
}

fn render_command(command: &Command) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(OsStr::to_string_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    format!("{program} {args}")
}
