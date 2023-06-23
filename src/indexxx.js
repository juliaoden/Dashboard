const fileNamesJuiceShop = {
  dastZap: "reports/dast-zap-report.json",
  gitleaks: "reports/gitleaks_report.json",
  sastSemgrep: "reports/semgrep-results.json",
  scaPackageDependency: "reports/dependency-check-report.json",
  trivy: "reports/trivy-report.json",
};

// {name: ["LOW", "link"]}

async function readVulnerabilities(fileNames, tableId) {
  const data = {}

  // Gitleaks
  const gitleaks = await fetch(fileNames.gitleaks).then((response) => response.json()).then((data) => data);
  gitleaks.forEach((problem) => {
    const name = problem.Description;

    if(!data.hasOwnProperty(name)) data[name] = ['', ''];
  });

  // Semgrep
  const semgrep = await fetch(fileNames.sastSemgrep).then((response) => response.json()).then((data) => data);
  semgrep.results.forEach((result) => {
    const name = result.extra.metadata.cwe[0].split(":")[0];
    const severity = result.extra.metadata.impact;
    const reference = result.extra.metadata.references[0];

    if(!data.hasOwnProperty(name)) data[name] = [severity, reference];
  }); 

  // Trivy
  const trivy = await fetch(fileNames.trivy).then((response) => response.json()).then((data) => data);
  trivy.Results.forEach((vulnerabilities) => {
    if (vulnerabilities.Vulnerabilities) {
      Object.values(vulnerabilities.Vulnerabilities).forEach((vul) => {
        const name = vul.VulnerabilityID;
        const severity = vul.Severity;
        const reference = vul.PrimaryURL;

        if(!data.hasOwnProperty(name)) data[name] = [severity, reference];       
      });
    }
    if (vulnerabilities.Secrets) {
      const name = vulnerabilities.Secrets[0].Title;
      const severity = vulnerabilities.Secrets[0].Severity;

      if(!data.hasOwnProperty(name)) data[name] = [severity, ''];
    }    
  });  

  // Sca-package-dependy-check
  const dependencyCheck = await fetch(fileNames.scaPackageDependency).then((response) => response.json()).then((data) => data);
  dependencyCheck.dependencies.forEach(dep => {
    if(dep.hasOwnProperty("vulnerabilities")){
      dep.vulnerabilities.forEach(vul => {
        const name = vul.name;
        const severity = vul.severity;
        const reference = vul.references[0].url;
        if(!data.hasOwnProperty(name)) data[name] = [severity, reference];
      });   
    }
  });

  // Dast-zap
  const dast = await fetch(fileNames.dastZap).then((response) => response.json()).then((data) => data);
  dast.site[0].alerts.forEach((alert) => {
    const name = `CWE-${alert.cweid}`;
    const severity = alert.riskdesc;
    const reference = removeHtmlTags(alert.reference);    

    if(alert.cweid > 0 && !data.hasOwnProperty(name)) data[name] = [severity, reference];
  });

  addRow(data, tableId);
}

function addRow( data, tableId) {
  const table = document.getElementById(tableId);

  for(const key in data){
    const row = table.insertRow(table.rows.length); // Insert a row at the end
    // Name
    const cell1 = row.insertCell(0); // Insert a cell in the first column
    cell1.innerHTML = key; // Add data to the cells

    // Priorität
    const cell2 = row.insertCell(1);
    cell2.innerHTML = data[key][0];

    // Referenz
    const cell3 = row.insertCell(2);
    // Link erstellen
    var link = document.createElement("a");
    link.href = data[key][1];
    link.textContent = "Weitere Informationen zum Sicherheitsproblem";
    // Link zur Zelle hinzufügen
    cell3.appendChild(link); 
  }
}

function removeHtmlTags(str) {
  var parser = new DOMParser();
  var parsedString = parser.parseFromString(str, 'text/html');
  return parsedString.body.textContent;
}

// readVulnerabilities(fileNamesTodoList, 'dashboard-todolist')
readVulnerabilities(fileNamesJuiceShop, "dashboard-juiceshop");


