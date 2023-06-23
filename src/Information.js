import { Table } from "./Table";
import "./Information.css";
import { useEffect, useState } from "react";

export default function Information({ tool, description, content }) {
  const [isTool, setIsTool] = useState(false);

  useEffect(() => {
    Object.keys(content).length === 0 ? setIsTool(false) : setIsTool(true);
  }, [content]);

  return (
    <div className="information">
      <h2>{tool}</h2>
      <p>{description}</p>
      {isTool && <Table key={tool} tool={tool} data={content} />}
    </div>
  );
}
