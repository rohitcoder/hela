use std::{process::exit, collections::HashMap};
use prettytable::{Table, row};

use crate::utils::common::slack_alert;

use super::common::{self, print_error, redact_github_token};

pub async fn pipeline_failure(code_path: String, is_sast: bool, is_sca: bool, is_secret: bool, is_license_compliance: bool, policy_url: String, slack_url: String) {
    let mut pipeline_sast_sca_data = HashMap::new();
    let mut pipeline_secret_license_data = HashMap::new();

    let mut found_sast_issues = false;
    let mut found_sca_issues = false;
    let mut found_secret_issues = false;
    let mut found_license_issues = false;

    let mut exit_code = 1;
    let mut exit_msg = String::new();

    if !std::path::Path::new("/tmp/output.json").exists() {
        return;
    }
    let original_output = std::fs::read_to_string("/tmp/output.json").unwrap();
    let json_output: serde_json::Value = serde_json::from_str(&original_output).expect("Error parsing JSON");
    
    // start preparing results here
    let mut sast_results = Vec::new();
    let mut slack_alert_msg = String::new();
    // if code_path contains ghp_* thend redact that value because its token
    let redacted_code_path = redact_github_token(&code_path);

    slack_alert_msg.push_str(format!("\n\n 🔎 Hela Security Scan Results for {}", redacted_code_path).as_str());
    println!("\n\n 🔎 Hela Security Scan Results for {}", redacted_code_path);
    if is_sast {

      let mut pipeline_sast_data: HashMap<&str, i64> = HashMap::new();
      let mut warning_count = 0;
      let mut info_count = 0;
      let mut error_count = 0;
      let mut critical_count = 0;
      let mut high_count = 0;
      let mut medium_count = 0;
      let mut low_count = 0;

      for result in json_output["sast"].as_array().unwrap() {
          let mut sast_result = HashMap::new();
          sast_result.insert("check_id", result["check_id"].as_str().unwrap());
          sast_result.insert("path", result["path"].as_str().unwrap());
          sast_result.insert("severity", result["extra"]["severity"].as_str().unwrap());
          sast_result.insert("message", result["extra"]["message"].as_str().unwrap());
          sast_result.insert("lines", result["extra"]["lines"].as_str().unwrap());
          
          if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "warning" {
              warning_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "info" {
              info_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "error" {
              error_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "critical" {
              critical_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "high" {
              high_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "medium" {
              medium_count += 1;
          } else if result["extra"]["severity"].as_str().unwrap().to_lowercase() == "low" {
              low_count += 1;
          }
          sast_results.push(sast_result);
      }
      pipeline_sast_data.insert("high_count", high_count);
      pipeline_sast_data.insert("critical_count", critical_count);
      pipeline_sast_data.insert("medium_count", medium_count);
      pipeline_sast_data.insert("low_count", low_count);
      pipeline_sast_data.insert("info_count", info_count);
      pipeline_sast_data.insert("warning_count", warning_count);
      pipeline_sast_data.insert("error_count", error_count);

      let mut table = Table::new();

      if sast_results.len() > 0 {
        found_sast_issues = true;
        println!("\n\n");
        println!("\t\t ================== SAST Results ==================");
        slack_alert_msg.push_str("\n\n");
        slack_alert_msg.push_str("\t\t ================== SAST Results ==================");
      }

      table.add_row(row![bFg->"S.No", bFg->"Path", bFg->"Severity", bFg->"Message"]);
      let mut sast_count = 0;
      for result in sast_results {
          sast_count += 1;
          // strip message to 50 characters
          table.add_row(row![sast_count, result["path"], result["severity"], result["message"].chars().take(50).collect::<String>()]);
          slack_alert_msg.push_str(&format!("\n\nPath: {}\nSeverity: {}\nMessage: {}", result["path"], result["severity"], result["message"]));
      }
      pipeline_sast_sca_data.insert("sast", pipeline_sast_data.clone());
    }


    if is_sca {
      
      let mut pipline_sca_data = HashMap::new();
      let mut warning_count = 0;
      let mut info_count = 0;
      let mut error_count = 0;
      let mut critical_count = 0;
      let mut high_count = 0;
      let mut medium_count = 0;
      let mut low_count = 0;

      // lets prepare list of Vulnerabilities with package name, version, ecosytem in each vulnerability
        if json_output["sca"].as_object().is_some() {
            for (manifest_file, sca_result) in json_output["sca"].as_object().unwrap() {
                let mut vulnerabilities = Vec::new();
                if sca_result["packages"].as_array().unwrap().len() == 0 {
                    continue;
                }
            for package in sca_result["packages"].as_array().unwrap() {
            let mut vulnerability = HashMap::new();
            vulnerability.insert("package", package["package"]["name"].as_str().unwrap());
            vulnerability.insert("version", package["package"]["version"].as_str().unwrap());
            vulnerability.insert("ecosystem", package["package"]["ecosystem"].as_str().unwrap());
            let mut vulns_list = Vec::new();
            for vuln in package["vulnerabilities"].as_array().unwrap() {
                let mut severity = vuln["database_specific"]["severity"].as_str().unwrap();
                if severity == "MODERATE" {
                    severity = "MEDIUM";
                }
                vulnerability.insert("summary", vuln["summary"].as_str().unwrap());
                vulnerability.insert("details", vuln["details"].as_str().unwrap());
                vulnerability.insert("severity", severity);

                let cwe_id_array = vuln["database_specific"]["cwe_ids"].as_array().unwrap();
                if cwe_id_array.len() > 0 {
                    vulnerability.insert("cwe_id", cwe_id_array[0].as_str().unwrap());
                }else{
                    vulnerability.insert("cwe_id", "");
                }
                
                let aliases_array = vuln["aliases"].as_array().unwrap();
                if aliases_array.len() > 0 {
                    vulnerability.insert("aliases", aliases_array[0].as_str().unwrap());
                }else{
                    vulnerability.insert("aliases", "");
                }

                if severity.to_lowercase() == "warning" {
                    warning_count += 1;
                } else if severity.to_lowercase() == "info" {
                    info_count += 1;
                } else if severity.to_lowercase() == "error" {
                    error_count += 1;
                } else if severity.to_lowercase() == "critical" {
                    critical_count += 1;
                } else if severity.to_lowercase() == "high" {
                    high_count += 1;
                } else if severity.to_lowercase() == "medium" {
                    medium_count += 1;
                } else if severity.to_lowercase() == "low" {
                    low_count += 1;
                }
                vulns_list.push(vulnerability.clone());
            }
            for vuln in vulns_list {
                vulnerabilities.push(vuln);
            }
        }
            if vulnerabilities.len() > 0 {
                found_sca_issues = true;
                println!("\n\n");
                println!("\t\t ================== SCA Results for {} ==================", manifest_file);
                slack_alert_msg.push_str(&format!("\n\n\t\t ================== SCA Results for {} ==================", manifest_file));
            }
            let mut table = Table::new();
            table.add_row(row![bFg->"S.No", bFg->"Package", bFg->"Severity", bFg->"Summary", bFg->"CWE ID", bFg->"Aliases"]);
            let mut sca_count = 0;

            for result in vulnerabilities {
                sca_count += 1;
                // strip summary to 50 characters
                table.add_row(row![sca_count, format!("{}@{}", result["package"], result["version"]), result["severity"], result["summary"].chars().take(50).collect::<String>(), result["cwe_id"], result["aliases"]]);
                slack_alert_msg.push_str(&format!("\n\nPackage: {}\nSeverity: {}\nSummary: {}\nCWE ID: {}\nAliases: {}", format!("{}@{}", result["package"], result["version"]), result["severity"], result["summary"], result["cwe_id"], result["aliases"]));
            }
            table.printstd();
            }
        }

        pipline_sca_data.insert("high_count", high_count);
        pipline_sca_data.insert("critical_count", critical_count);
        pipline_sca_data.insert("medium_count", medium_count);
        pipline_sca_data.insert("low_count", low_count);
        pipline_sca_data.insert("info_count", info_count);
        pipline_sca_data.insert("warning_count", warning_count);
        pipline_sca_data.insert("error_count", error_count);

        pipeline_sast_sca_data.insert("sca", pipline_sca_data);
    }
    
    let mut total_secrets_exposed = 0;
    if is_secret {
      let mut detected_detectors = Vec::new();
    
      let mut secret_results = Vec::new();
      let mut total_secrets = 0;
      for result in json_output["secret"]["results"].as_array().unwrap() {
        total_secrets_exposed += 1;
          let line_number = match result["SourceMetadata"]["Data"]["Filesystem"]["line"].as_i64() {
              Some(line_number) => line_number,
              None => 0,
          };
          let number_string = line_number.to_string();
          let secret_result = {
              let mut secret_result = HashMap::new();
              secret_result.insert("file", result["SourceMetadata"]["Data"]["Filesystem"]["file"].to_string());
              secret_result.insert("line", number_string);
              secret_result.insert("raw", result["Raw"].to_string());
              secret_result.insert("detector_name", result["DetectorName"].to_string().to_uppercase());
              secret_result.insert("decoder_name", result["DecoderName"].to_string());
              secret_result
          };
          secret_results.push(secret_result);
          if !detected_detectors.contains(&result["DetectorName"].as_str().unwrap().to_string().to_uppercase()) {
              detected_detectors.push(result["DetectorName"].as_str().unwrap().to_string().to_uppercase());
          }
      }
      
      detected_detectors = detected_detectors.iter().map(|x| x.to_string()).collect::<Vec<String>>();
      pipeline_secret_license_data.insert("detected_detectors", detected_detectors);


      let mut table = Table::new();
      if secret_results.clone().len() > 0 {
        found_secret_issues = true;
        println!("\n\n");
        println!("\t\t ================== Secret Results ==================");
        slack_alert_msg.push_str("\n\n");
        slack_alert_msg.push_str("================== Secret Results ==================");
        table.add_row(row![bFg->"S.No", bFg->"File", bFg->"Line", bFg->"Raw", bFg->"Detector Name"]);
      }

      let mut secret_count = 0;
        for value in secret_results.clone() {
            secret_count += 1;
            // strip raw to 50 characters also remove double quotes by replacing with empty string
            table.add_row(row![secret_count, value["file"].replace("\"", ""), value["line"], value["raw"].replace("\"", ""), value["detector_name"].replace("\"", "")]);
            slack_alert_msg.push_str(&format!("\n\nFile: {}\nLine: {}\nRaw: {}\nDetector Name: {}", value["file"], value["line"], value["raw"], value["detector_name"]));
        }
        if secret_results.len() > 0 {
            table.printstd();
        }
    }

    if is_license_compliance {

        let mut licenses_list = Vec::new();

        let mut license_results = HashMap::new();
        for (manifest, license_detail) in json_output["license"].as_object().unwrap() {
          
          let mut detected_licenses = Vec::new();
          for (package_name, licenses) in license_detail.as_object().unwrap() {
            let mut license_details = HashMap::new();
            license_details.insert(package_name, licenses.clone());
            detected_licenses.push(license_details.get(package_name).unwrap().clone());
          }
          license_results.insert(manifest, license_detail);

          for license in detected_licenses.iter() {
            for license in license.as_array().unwrap() {
                if !licenses_list.contains(&license.as_str().unwrap().to_string()) {
                    licenses_list.push(license.as_str().unwrap().to_string());
                }
            }
          }
          if license_results.len() > 0 {
            println!("\n\n");
            println!("\t\t ================== License Details for {} ==================", manifest);
            slack_alert_msg.push_str(&format!("\n\n================== License Details for {} ==================", manifest));
          }
          let mut table = Table::new();
          table.add_row(row![bFg->"S.No", bFg->"Package", bFg->"Licenses"]);
          let mut license_count = 0;
          for (package_name, licenses) in license_detail.as_object().unwrap() {
            license_count += 1;
            // lets create license arary
            let mut license_array = Vec::new();
            for license in licenses.as_array().unwrap() {
                license_array.push(license.as_str().unwrap());
            }
            table.add_row(row![license_count, package_name, license_array.join(", ")]);
            slack_alert_msg.push_str(&format!("\n\nPackage: {}\nLicenses: {}", package_name, license_array.join(", ")));
          }
          table.printstd();
      }
      licenses_list = licenses_list.iter().map(|x| x.to_lowercase()).collect::<Vec<String>>();
      pipeline_secret_license_data.insert("licenses", licenses_list);
    }

    if found_sast_issues == false && found_sca_issues == false && found_secret_issues == false && found_license_issues == false {
        println!("\n\n\t\t\t No issues found in scan results");
    }

    // Policy implementation
    if !policy_url.is_empty() {
        let mut is_pipeline_failed = false;
        let mut pipeline_failure_reason = String::new();
        // if policy_url starts with http or https then we will fetch policy file from url else we will read it from local file system
        let mut policy_yaml: serde_yaml::Value = serde_yaml::Value::Null;
        if policy_url.starts_with("http") {
            let policy_yaml_string = match reqwest::get(policy_url).await {
                Ok(response) => {
                    match response.text().await {
                        Ok(text) => text,
                        Err(e) => {
                            print_error(format!("Error: Invalid or unable to reach policy file, please contact support team! : {:?}", e.to_string()).as_str(), 101);
                            return;
                        }
                    }
                },
                Err(e) => {
                    print_error(format!("Error: Invalid or unable to reach policy file, please contact support team! : {:?}", e.to_string()).as_str(), 101);
                    return;
                }
            };
            policy_yaml = match serde_yaml::from_str(&policy_yaml_string) {
                Ok(value) => value,
                Err(e) => {
                    print_error(format!("Error: Invalid or unable to reach policy file, please contact support team! : {:?}", e.to_string()).as_str(), 101);
                    return;
                }
            };
        }else{
            let policy_yaml_string = match std::fs::read_to_string(policy_url) {
                Ok(text) => text,
                Err(e) => {
                    print_error(format!("Error: Invalid or unable to reach policy file, please contact support team! : {:?}", e.to_string()).as_str(), 101);
                    return;
                }
            };
            policy_yaml = match serde_yaml::from_str(&policy_yaml_string) {
                Ok(value) => value,
                Err(e) => {
                    print_error(format!("Error: Invalid or unable to reach policy file, please contact support team! : {:?}", e.to_string()).as_str(), 101);
                    return;
                }
            };
        }
        let policy_json = policy_yaml.as_mapping().unwrap();
        let mut sast_policy = None;
        let mut sca_policy = None;
        let mut secret_policy = None;
        let mut license_policy = None;

        for (key, value) in policy_json {
            if key.as_str().unwrap() == "sast" {
                sast_policy = Some(value);
            }
            if key.as_str().unwrap() == "sca" {
                sca_policy = Some(value);
            }
            if key.as_str().unwrap() == "secret" {
                secret_policy = Some(value);
            }
            if key.as_str().unwrap() == "license" {
                license_policy = Some(value);
            }
        }

        // now lets write logic to check policy against scan results since we have all data in pipeline_sast_sca_data and pipeline_secret_license_data

        if is_sast && sast_policy.is_some() {
            let sast_policy = sast_policy.unwrap().as_mapping().unwrap();
            for (key, value) in sast_policy {
                let key = key.as_str().unwrap();
                let value = value.as_mapping().unwrap();
                let operator = value.get(&serde_yaml::Value::String("operator".to_string())).unwrap().as_str().unwrap();
                let value = value.get(&serde_yaml::Value::String("value".to_string())).unwrap().as_i64().unwrap();
                let pipeline_sast_data = pipeline_sast_sca_data.get("sast").unwrap();
                let pipeline_sast_data = pipeline_sast_data.get(key).unwrap();
                if operator == "greater_than" {
                    if pipeline_sast_data > &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is greater than {}", key, pipeline_sast_data, value);
                    }
                }else if operator == "less_than" {
                    if pipeline_sast_data < &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is less than {}", key, pipeline_sast_data, value);
                    }
                }else if operator == "equal_to" {
                    if pipeline_sast_data == &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is equal to {}", key, pipeline_sast_data, value);
                    }
                }
            }
            exit_code = common::EXIT_CODE_SAST_FAILED;
            exit_msg = common::SAST_FAILED_MSG.to_string();
        }

        if is_sca && sca_policy.is_some() {
            let sca_policy = sca_policy.unwrap().as_mapping().unwrap();
            for (key, value) in sca_policy {
                let key = key.as_str().unwrap();
                let value = value.as_mapping().unwrap();
                let operator = value.get(&serde_yaml::Value::String("operator".to_string())).unwrap().as_str().unwrap();
                let value = value.get(&serde_yaml::Value::String("value".to_string())).unwrap().as_i64().unwrap();
                let pipeline_sca_data = pipeline_sast_sca_data.get("sca").unwrap();
                let pipeline_sca_data = pipeline_sca_data.get(key).unwrap();
                if operator == "greater_than" {
                    if pipeline_sca_data > &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is greater than {}", key, pipeline_sca_data, value);
                    }
                }else if operator == "less_than" {
                    if pipeline_sca_data < &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is less than {}", key, pipeline_sca_data, value);
                    }
                }else if operator == "equal_to" {
                    if pipeline_sca_data == &value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} count is {} which is equal to {}", key, pipeline_sca_data, value);
                    }
                }
            }
            exit_code = common::EXIT_CODE_SCA_FAILED;
            exit_msg = common::SCA_FAILED_MSG.to_string();
        }
        
        if is_secret && secret_policy.is_some() {
            let secret_policy = secret_policy.unwrap().as_mapping().unwrap();
            if secret_policy.contains_key(&serde_yaml::Value::String("contains".to_string())) {
                let contains = secret_policy.get(&serde_yaml::Value::String("contains".to_string())).unwrap().as_sequence().unwrap();
                let pipeline_secret_data = pipeline_secret_license_data.get("detected_detectors").unwrap();
                for detector in pipeline_secret_data.iter() {
                    if contains.contains(&serde_yaml::Value::String(detector.to_string())) {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} is present in blocked list", detector);
                    }
                }
            }

            for (_key, operator) in secret_policy {
                if secret_policy.get("value").is_none() {
                    continue;
                }
                let value  = secret_policy.get("value").unwrap().as_i64().unwrap();
                if operator == "greater_than" {
                    if total_secrets_exposed > value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} secrets exposed  which is greater than {}",  total_secrets_exposed, value);
                    }
                }else if operator == "less_than" {
                    if total_secrets_exposed < value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} secrets exposed  which is less than {}",  total_secrets_exposed, value);
                    }
                }else if operator == "equal_to" {
                    if total_secrets_exposed == value {
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} secrets exposed  which is equal to {}",  total_secrets_exposed, value);
                    }
                }
            }

            exit_code = common::EXIT_CODE_SECRET_FAILED;
            exit_msg = common::SECRET_FAILED_MSG.to_string();
        }
        if is_license_compliance && license_policy.is_some() {
            let license_policy = license_policy.unwrap().as_mapping().unwrap();
            if license_policy.contains_key(&serde_yaml::Value::String("contains".to_string())) {
                let contains = license_policy.get(&serde_yaml::Value::String("contains".to_string())).unwrap().as_sequence().unwrap();
                let contains = contains.iter().map(|x| x.as_str().unwrap().to_lowercase()).collect::<Vec<String>>();
                let pipeline_license_data = pipeline_secret_license_data.get("licenses").unwrap();
                for license in pipeline_license_data.iter() {
                    if contains.contains(&license.to_string().to_lowercase()) { 
                        is_pipeline_failed = true;
                        pipeline_failure_reason = format!("Pipeline failed because {} license is present in blocked list", license);
                    }
                }
            }
            exit_code = common::EXIT_CODE_LICENSE_FAILED;
            exit_msg = common::LICENSE_FAILED_MSG.to_string();
        }
        if is_pipeline_failed {
            println!("\n\n");
            println!("\t\t ================== ❌ Pipeline Failed ==================");
            println!("\t\t Reason: {}", pipeline_failure_reason);
            println!("\n\n");
            println!("\t\t {}", exit_msg);
            println!("\n\n");
            slack_alert_msg.push_str(&format!("\n\n================== ❌ Pipeline Failed ==================\n\t\t Reason: {}\n\n\n\t\t {}", pipeline_failure_reason, exit_msg));
            slack_alert(&slack_url, &slack_alert_msg).await;
            // finish everything and smoothly exit
            exit(exit_code);
        }else{
            println!("\n\n");
            println!("\t\t ================== ✅ Pipeline Passed ==================");
            slack_alert_msg.push_str("\n\n\t\t ================== ✅ Pipeline Passed ==================");
            slack_alert(&slack_url, &slack_alert_msg).await;
            println!("\n\n");
        }
    }else{
        println!("\n\n");
        println!("\t\t ================== ✅ Pipeline Passed ==================");
        slack_alert_msg.push_str("\n\n================== ✅ Pipeline Passed ==================");
        slack_alert(&slack_url, &slack_alert_msg).await;
        println!("\n\n");
    }
}
