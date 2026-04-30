import type { Metadata } from "next";
import SarifDemoClient from "./SarifDemoClient";

export const metadata: Metadata = {
  title: "SARIF Viewer Demo — Lyrie",
  description: "Interactive SARIF 2.1.0 viewer component demo",
};

export default function SarifDemoPage() {
  return <SarifDemoClient />;
}
