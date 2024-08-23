## Hela 
![Build Status](https://app.travis-ci.com/rohitcoder/hela.svg?branch=main)

This tool helps in running Static Code Analysis (SCA), Static Application Security Testing (SAST), Secret scanning, and License compliance scanning on your project. It also allows you to write your own policy files in YAML format to enforce blocking in pipelines when security issues are detected.

### Docker Installation
To use the tool without building from the source and installing Rust dependencies, you can run it using Docker. Follow the instructions below:

1. Pull the Docker image:

```shell
docker pull rohitcoder/hela
```

2. Run the tool using Docker:

```shell
docker run rohitcoder/hela <tool-options>
```

Add any Docker options you may need (e.g., volume mounting), and <tool-options> with the desired tool options explained in the next section.

### Usage
To run the Hela Tool, use the following command:

```shell
docker run rohitcoder/hela --code-path <path> --sast --sca --secret --license-compliance --policy-url <policy_url> --verbose
```
Replace ``<path>`` with the path to your project, which can be either a local folder path or a Git repository URL. If you want to use it with a private repository, provide the Git repository path with an access token.

Replace ``<policy_url> ``with the URL of your policy file in YAML format. This file defines rules for blocking pipelines when specific security issues are detected.

The tool will execute the specified scans (``--license-compliance``, ``--sast``, ``--sca``, ``--secret``) on your project and enforce the policies defined in the policy file. Verbose mode (``--verbose``) will provide detailed output.

Note: The API endpoints and start-server functionality are currently in development and not available.

## Building & Installation from Source

Clone and build the project:

```shell
git clone https://github.com/rohitcoder/hela.git
cd hela
cargo build --release
```

## CLI Usage
To use the tool from the command line, run the following command:

```shell
cargo run -- [options]
```
Replace ``[options]`` with the desired options from the list below.

### Options
<table>
   <thead>
      <tr>
         <th>Option</th>
         <th>Description</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>-v, --verbose</td>
         <td>Enable verbose mode.</td>
      </tr>
      <tr>
         <td>
            -p 
            <path>
            , --code-path 
            <path>
         </td>
         <td>Pass the path of the project to scan (local path or HTTP Git URL).</td>
      </tr>
      <tr>
         <td>
            -t 
            <path>
            , --rule-path
            <path>
         </td>
         <td>Pass the path of the semgrep rules repository (local path or HTTP Git URL).</td>
      </tr>
      <tr>
         <td>
            -n 
            <path>
            , --no-install
            <path>
         </td>
         <td>Use this option to skip installation of project during SCA scan (Useful when you already have lock files in repo, and you want to save time).</td>
      </tr>
      <tr>
         <td>
            -r 
            <path>
            , --root-only
            <path>
         </td>
         <td>Pass this flag, if you want to run SCA for only root folder manifests.</td>
      </tr>
      <tr>
         <td>
            -d
            <path>
            , --build-args
            <path>
         </td>
         <td>Provide any additional build arguments for SCA scan (This will be injected in build commands like mvn build or npm run)</td>
      </tr>
      <tr>
         <td>
            -
            <path>
            , --manifests
            <path>
         </td>
         <td>Pass list of manifests type to scan (comma separated values). Example: --manifests packages-lock.json,requirements.txt</td>
      </tr>
      <tr>
         <td>
            -i 
            <commit_id>
            , --commit-id 
            <commit_id>
         </td>
         <td>Pass the commit ID to scan (optional).</td>
      </tr>
      <tr>
         <td>
            -b 
            <branch>
            , --branch 
            <branch>
         </td>
         <td>Pass the branch name to scan (optional).</td>
      </tr>
      <tr>
         <td>-s, --sast</td>
         <td>Run SAST scan.</td>
      </tr>
      <tr>
         <td>
            -u 
            <server_url>
            , --server-url 
            <server_url>
         </td>
         <td>Pass the server URL to post scan results.</td>
      </tr>
      <tr>
         <td>-c, --sca</td>
         <td>Run SCA scan.</td>
      </tr>
      <tr>
         <td>-e, --secret</td>
         <td>Run Secret scan.</td>
      </tr>
      <tr>
         <td>-l, --license-compliance</td>
         <td>Run License Compliance scan.</td>
      </tr>
      <tr>
         <td>-j, --json</td>
         <td>Print JSON output. Note: This won't work with pipeline check implementation.</td>
      </tr>
      <tr>
         <td>
            -y 
            <policy_url>
            , --policy-url 
            <policy_url>
         </td>
         <td>Pass the policy URL to check if the pipeline should fail.</td>
      </tr>
   </tbody>
</table>

### Write a Pipelien failure Policy Rule

You can use these policy to fail your pipleine builds in your CI/CD flow. Scanner will check for the conditions defined in the policy file and will fail the pipeline if any of the condition is met.

```yaml
## list in which conditions our pipeline should fail
sast:
  critical_count:
    operator: greater_than ## supports greater_than, less_than, equal_to
    value: 2
  high_count:
    operator: greater_than
    value: 2

sca:
  critical_count:
    operator: greater_than
    value: 2
  high_count:
    operator: greater_than
    value: 1

secret:
  contains:
  - JDBC # supports abbysale,abstract,abuseipdb,accuweather,adafruitio,adobeio,adzuna,aeroworkflow,agora,aha,airbrakeprojectkey,airbrakeuserkey,airship,airtableapikey,airvisual,aiven,alchemy,alconost,alegra,aletheiaapi,algoliaadminkey,alibaba,alienvault,allsports,amadeus,ambee,amplitudeapikey,anypoint,apacta,api2cart,apideck,apiflash,apifonica,apify,apilayer,apimatic,apiscience,apitemplate,apollo,appcues,appfollow,appointedd,appsynergy,apptivo,artifactory,artsy,asanaoauth,asanapersonalaccesstoken,assemblyai,atera,audd,auth0managementapitoken,auth0oauth,autodesk,autoklose,autopilot,avazapersonalaccesstoken,aviationstack,aws,axonaut,aylien,ayrshare,azure,bannerbear,baremetrics,baseapiio,beamer,beebole,besnappy,besttime,billomat,bitbar,bitcoinaverage,bitfinex,bitlyaccesstoken,bitmex,blablabus,blazemeter,blitapp,blocknative,blogger,bombbomb,boostnote,borgbase,braintreepayments,brandfetch,browserstack,browshot,bscscan,buddyns,bugherd,bugsnag,buildkite,buildkitev2,bulbul,bulksms,buttercms,caflou,calendarific,c...e,telnyx,terraformcloudpersonaltoken,testingbot,text2data,textmagic,theoddsapi,thinkific,thousandeyes,ticketmaster,tickettailor,tiingo,timecamp,timezoneapi,tineswebhook,tly,tmetric,todoist,toggltrack,tokeet,tomorrowio,tomtom,tradier,transferwise,travelpayouts,travisci,trelloapikey,tru,trufflehogenterprise,twelvedata,twilio,twist,twitch,twitter,tyntec,typeform,typetalk,ubidots,uclassify,unifyid,unplugg,unsplash,upcdatabase,uplead,uploadcare,uptimerobot,upwave,uri,urlscan,user,userflow,userstack,vatlayer,vbout,vercel,verifier,verimail,veriphone,versioneye,viewneo,virustotal,visualcrossing,voicegain,voodoosms,vouchery,vpnapi,vultrapikey,vyte,walkscore,weatherbit,weatherstack,webex,webflow,webscraper,webscraping,websitepulse,wepay,whoxy,wistia,wit,worksnaps,workstack,worldcoinindex,worldweather,wrike,yandex,yelp,youneedabudget,yousign,youtubeapikey,zapierwebhook,zendeskapi,zenkitapi,zenrows,zenscrape,zenserp,zeplin,zerobounce,zipapi,zipbooks,zipcodeapi,zipcodebase,zonkafeedback,zulipchat

license:
  contains:
  - AGPL
  - GPL
  - LGPL
```

## Example working command
```shell
docker run rohitcoder/hela --code-path https://github.com/appsecco/dvja --license-compliance --sast --sca --secret --license-compliance --policy-url https://raw.githubusercontent.com/rohitcoder/code-security-policies/main/policy-fail.yaml --verbose
```

## 💪 Contributors
Thank you for continuously making this tool better! 🙏

<a href="https://github.com/rohitcoder/hela/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=rohitcoder/hela" />
</a>

### Contribute

Please go through the [contributing guidelines](https://github.com/rohitcoder/hela/blob/main/CONTRIBUTING.md) before you start, and let us know if you have any challenges or questions.


**Hela** is maintained by [Rohit Kumar (@rohitcoder)](https://github.com/rohitcoder)

Thank you!
