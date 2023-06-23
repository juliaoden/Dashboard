import "./Table.css";

export function Table({ tool, data }) {
  return (
    <div className="dashboard-table">
      <table id={`dashboard-${tool}`} className="dashboard">
        <thead>
          <tr>
            <th>Name</th>
            <th>Priorität</th>
            <th>Weiter Informationen</th>
          </tr>
        </thead>
        <tbody>
          {Object.keys(data).map((vul) => (
            <tr key={`row-${vul}`}>
              <td id="row-name">{vul}</td>
              <td>{data[vul][0]}</td>
              <td>
                <a href={data[vul][1]}>Weitere Informationen zu {vul}</a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
