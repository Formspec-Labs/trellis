// TWREF-003 / TWREF-039 — retired crate directory names must not reappear under
// stack workspace `crates/` trees (including stale Claude worktree snapshots).
//
// **Fail-closed:** When this crate runs inside `formspec-stack`, sibling workspaces must resolve.
// Standalone Trellis-only clones cannot resolve `formspec_stack_root()` — set
// `SKIP_STACK_DELETE_SURFACE_GUARD=1` for intentional skips (document in CI only when needed).
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical directory names for crates removed in the Trellis/WOS service-boundary cut.
/// Keep in sync with `TRELLIS-WOS-REFACTOR-TODO.md` delete checklist.
const RETIRED_CRATE_DIR_NAMES: &[&str] = &[
    "formspec-server-bundle-seeder",
    "trellis-cose",
    "trellis-export",
    "trellis-hpke",
    "trellis-interop-scitt",
    "trellis-interop-vc",
    "trellis-store-postgres",
    "trellis-store-postgres-shared",
    "trellis-verify",
    "wos-server-audit-postgres",
];

#[test]
fn given_retired_crate_denylist_when_scanning_stack_workspaces_then_no_residue_paths_exist() {
    // Given — a canonical denylist of removed crate roots (`RETIRED_CRATE_DIR_NAMES`).
    let stack_root = match formspec_stack_root() {
        Some(root) => root,
        None => {
            if std::env::var_os("SKIP_STACK_DELETE_SURFACE_GUARD").is_some() {
                return;
            }
            panic!(
                "stack delete-surface guard could not resolve formspec-stack root \
(trellis + workspec-server + formspec-server siblings).\n\
Run tests from the monorepo parent or export SKIP_STACK_DELETE_SURFACE_GUARD=1 for standalone clones."
            );
        }
    };
    let workspaces = [
        stack_root.join("trellis"),
        stack_root.join("workspec-server"),
        stack_root.join("formspec-server"),
    ];
    // When — scanning for those directory names under each workspace `crates/` root
    // and under `.claude/worktrees/*/crates/` (stale snapshots that confuse deletes/greps).
    let hits = collect_residue_hits(&workspaces, RETIRED_CRATE_DIR_NAMES);
    // Then — no matching paths remain on disk.
    assert!(
        hits.is_empty(),
        "retired crate dirs must not exist on disk — remove residue or refresh denylist intentionally.\n\
         hits:\n{}",
        hits.iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn formspec_stack_root() -> Option<PathBuf> {
    // Parent of submodule: `…/stack/trellis/crates/<this-test>` → `…/stack` in three hops.
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop(); // crates
    dir.pop(); // trellis submodule root
    dir.pop(); // formspec-stack (or unrelated parent if checkout is standalone)
    let stack_root = dir;
    (stack_root.join("trellis/Cargo.toml").is_file()
        && stack_root.join("workspec-server/Cargo.toml").is_file()
        && stack_root.join("formspec-server/Cargo.toml").is_file())
    .then_some(stack_root)
}

fn collect_residue_hits(workspaces: &[PathBuf], retired: &[&str]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    for workspace in workspaces {
        hits.extend(scan_crates_children(workspace.join("crates"), retired));
        hits.extend(scan_claude_worktree_crates(workspace, retired));
    }
    hits.sort();
    hits.dedup();
    hits
}

fn scan_crates_children(crates_dir: PathBuf, retired: &[&str]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    if !crates_dir.is_dir() {
        return hits;
    }
    for name in retired {
        let path = crates_dir.join(name);
        if path.exists() {
            hits.push(path);
        }
    }
    hits
}

fn scan_claude_worktree_crates(workspace: &Path, retired: &[&str]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let worktrees = workspace.join(".claude/worktrees");
    if !worktrees.is_dir() {
        return hits;
    }
    let snapshots = fs::read_dir(&worktrees).expect("read Claude worktrees");
    for snapshot in snapshots.filter_map(Result::ok) {
        let crates_dir = snapshot.path().join("crates");
        if crates_dir.is_dir() {
            hits.extend(scan_crates_children(crates_dir, retired));
        }
    }
    hits
}
