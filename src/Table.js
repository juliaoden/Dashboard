import "./Table.css"

export function Table({tool, data}){ 
    return (
        <div id="id" className="dashboard" key={tool}>
            <h2>Vulnerabilities found by {tool}</h2>
            <div>
                <table id={`dashboard-${tool}`} className="dashboard">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Priorität</th>
                            <th>Weiter Informationen</th>
                        </tr>
                    </thead>
                    <tbody >
                        {Object.keys(data).map(vul => 
                            <tr key={`row-${vul}`}>
                                <td>{vul}</td>
                                <td>{data[vul][0]}</td>
                                <td>{data[vul][1]}</td>
                            </tr>
                        )}
                    </tbody>                    
                </table>
            </div>
        </div>
    )
}