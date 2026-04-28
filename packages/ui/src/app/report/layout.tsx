/**
 * Report layout — standalone, no sidebar/header.
 * Matches the app's dark theme but without the command-center chrome.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export default function ReportLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className="bg-gray-950 text-gray-100 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
