## Code Security Tool
This tool helps in running Static Code Analysis (SCA), Static Application Security Testing (SAST), Secret scanning, and License compliance scanning on your project. It also allows you to write your own policy files in YAML format to enforce blocking in pipelines when security issues are detected.

### Docker Installation
To use the tool without building from source and installing Rust dependencies, you can run it using Docker. Follow the instructions below:

1. Pull the Docker image:

```shell
docker pull <docker-image>
```
Replace <docker-image> with the appropriate image name or tag.

2. Run the tool using Docker:

```shell
docker run <docker-options> code-security <tool-options>
```

Replace <docker-options> with any additional Docker options you may need (e.g., volume mounting), and <tool-options> with the desired tool options explained in the next section.

### Usage
To run the Code Security Tool, use the following command:

```shell
docker run code-security --path <path> --license-compliance --sast --sca --secret --license-compliance --policy-url <policy_url> --verbose
```
Replace ``<path>`` with the path to your project, which can be either a local folder path or a Git repository URL. If you want to use it with a private repository, provide the Git repository path with an access token.

Replace ``<policy_url> ``with the URL of your policy file in YAML format. This file defines rules for blocking pipelines when specific security issues are detected.

The tool will execute the specified scans (``--license-compliance``, ``--sast``, ``--sca``, ``--secret``) on your project and enforce the policies defined in the policy file. Verbose mode (``--verbose``) will provide detailed output.

Note: The API endpoints and start-server functionality are currently in development and not available.