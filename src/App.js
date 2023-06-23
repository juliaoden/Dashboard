import { useState } from 'react';
import './App.css';
import { Table } from './Table';
import gitleaks from './reports/gitleaks_report.json'
import semgrep from './reports/semgrep-results.json'

function App() {
  const data = {
    gitleaks: {},
    semgrep: {}
  };
 // {gitleaks: {name: [severity, reference], name: [severity, reference]}, semgrep: {name: [severity, reference]}}

  gitleaks.forEach((problem) => {
    const name = problem.Description;
    if(!data.gitleaks.hasOwnProperty(name)) data.gitleaks[name] = ['', '']
  });

  semgrep.results.forEach((result) => {
    const name = result.extra.metadata.cwe[0].split(":")[0];
    const severity = result.extra.metadata.impact;
    const reference = result.extra.metadata.references[0];

    if(!data.semgrep.hasOwnProperty(name)) data.semgrep[name] = [severity, reference];
  });   

  return (
    <>
      <h1>Vulnerability Dashboard</h1>
      {Object.keys(data).map(tool => <Table key={tool} tool={tool} data={data[tool]} />)}
    </>
  );
}

export default App;
