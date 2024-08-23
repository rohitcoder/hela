use super::common::execute_command;

pub async fn find_files_recursively(_path: &str, patterns: Vec<&str>, ignore_paths: Vec<&str>) -> Vec<String> {
    let mut manifests = Vec::new();
    let ignore_dirs: Vec<String> = ignore_paths
        .iter()
        .map(|x| format!("{}", x))
        .collect();
    let ignore_dirs_string = ignore_dirs.join(" ! -path ");
    for manifest in patterns.iter() {
        let mut find_command = format!("find {} -name {}", _path, manifest);
        if ignore_dirs.len() > 0 {
            find_command = format!("find {} -name {} ! -path {}", _path, manifest, ignore_dirs_string);
        }
        let find_output = execute_command(&find_command, true).await;
        let find_output_lines = find_output.lines();
        for line in find_output_lines {
            manifests.push(line.to_string());
        }
    }
    // replace // with / and remove those lines which are in in ignore_paths
    manifests = manifests
        .iter()
        .map(|x| x.replace("//", "/")).collect();
    // if any of ignore_paths is in any of manifests then remove that manifest from manifests
    for ignore_path in ignore_paths.iter() {
        manifests = manifests
            .iter()
            .filter(|x| !x.contains(ignore_path))
            .map(|x| x.to_string()).collect();
    }
    manifests
}