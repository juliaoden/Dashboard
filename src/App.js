import { useState } from "react";
import "./App.css";
import gitleaks from "./reports/gitleaks_report.json";
import semgrep from "./reports/semgrep-results.json";
import dependencyCheck from "./reports/dependency-check-report.json";
import trivy from "./reports/trivy-report.json";
import dast from "./reports/dast-zap-report.json";
import { Row, Col } from "react-bootstrap";
import { FaCheck } from "react-icons/fa";
import Information from "./Information";
import descriptions from "./description.json";

function App() {
  const data = {
    package: {},
    semgrep: {},
    gitleaks: {},
    dependencyCheck: {},
    publishContainer: {},
    trivy: {},
    dast: {},
    deploy: {},
  };
  // {gitleaks: {name: [severity, reference], name: [severity, reference]}, semgrep: {name: [severity, reference]}}
  // const [stages, setStages] = useState([
  //   "Package",
  //   "Semgrep",
  //   "Gitleaks",
  //   "Dependency Check",
  //   "Publish Container",
  //   "Trivy",
  //   "Dast-Zap",
  //   "Deploy",
  // ]);
  const [description, setDescription] = useState();
  const [content, setContent] = useState();
  const [tool, setTool] = useState();

  function removeHtmlTags(str) {
    var parser = new DOMParser();
    var parsedString = parser.parseFromString(str, "text/html");
    return parsedString.body.textContent;
  }

  gitleaks.forEach((problem) => {
    const name = problem.Description;
    if (!data.gitleaks.hasOwnProperty(name)) data.gitleaks[name] = ["", ""];
  });

  semgrep.results.forEach((result) => {
    const name = result.extra.metadata.cwe[0].split(":")[0];
    const severity = result.extra.metadata.impact;
    const reference = result.extra.metadata.references[0];

    if (!data.semgrep.hasOwnProperty(name))
      data.semgrep[name] = [severity, reference];
  });

  dependencyCheck.dependencies.forEach((dep) => {
    if (dep.hasOwnProperty("vulnerabilities")) {
      dep.vulnerabilities.forEach((vul) => {
        const name = vul.name;
        const severity = vul.severity;
        const reference = vul.references[0].url;
        if (!data.dependencyCheck.hasOwnProperty(name))
          data.dependencyCheck[name] = [severity, reference];
      });
    }
  });

  trivy.Results.forEach((vulnerabilities) => {
    if (vulnerabilities.Vulnerabilities) {
      Object.values(vulnerabilities.Vulnerabilities).forEach((vul) => {
        const name = vul.VulnerabilityID;
        const severity = vul.Severity;
        const reference = vul.PrimaryURL;

        if (!data.trivy.hasOwnProperty(name))
          data.trivy[name] = [severity, reference];
      });
    }
    if (vulnerabilities.Secrets) {
      const name = vulnerabilities.Secrets[0].Title;
      const severity = vulnerabilities.Secrets[0].Severity;

      if (!data.trivy.hasOwnProperty(name)) data.trivy[name] = [severity, ""];
    }
  });

  dast.site[0].alerts.forEach((alert) => {
    const name = `CWE-${alert.cweid}`;
    const severity = alert.riskdesc;
    const reference = removeHtmlTags(alert.reference);

    if (alert.cweid > 0 && !data.dast.hasOwnProperty(name))
      data.dast[name] = [severity, reference];
  });

  function renderTable(e) {
    const clickedButton = e.target.innerHTML;
    Object.keys(descriptions).forEach((desc) => {
      if (desc === clickedButton) {
        setDescription(descriptions[desc]);
      }
    });
    setTool(clickedButton);
    setContent(data[clickedButton]);
  }

  return (
    <>
      <h1>Vulnerability Dashboard</h1>
      <Row className="row">
        <Col sm={3} className="pipeline">
          {Object.keys(data).map((tool) => (
            <div key={tool} className="pipeline-item">
              <div id="logo">
                <FaCheck />
              </div>
              <button onClick={renderTable}>{tool}</button>
            </div>
          ))}
        </Col>
        <Col sm={9} className="information">
          {content && (
            <Information
              tool={tool}
              description={description}
              content={content}
            />
          )}
        </Col>
      </Row>
    </>
  );
}

export default App;
