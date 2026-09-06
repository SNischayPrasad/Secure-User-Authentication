import { Link } from "react-router-dom";
import { Button } from "../components/Button";

export function NotFound() {
  return (
    <div className="shell centre-note">
      <p className="eyebrow" style={{ justifyContent: "center" }}>
        404
      </p>
      <h1>No document at this address.</h1>
      <p className="lede">The page you asked for does not exist. The links below still work.</p>
      <div className="row" style={{ justifyContent: "center" }}>
        <Link to="/">
          <Button variant="primary">Go to the front page</Button>
        </Link>
        <Link to="/dashboard">
          <Button>Open dashboard</Button>
        </Link>
      </div>
    </div>
  );
}
