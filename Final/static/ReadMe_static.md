# RedTeamForge Display Dashboard
This directory stores the entirely static content forming the web interface. Because it is purely static, parsing it implies zero overhead for the python context.

### The Stack:
- **`index.html`**: The document object model mapping a responsive, dark-mode, glassmorphism layout composed of inputs and a "Feed List" log.
- **`style.css`**: Heavily stylized with variable-driven neon glows, backdrop blurs, and localized CSS animations (`@keyframes`) for aesthetic micro-interactions.
- **`app.js`**: Vanilla Javascript enforcing "live-polling". Rather than websockets, it securely triggers lightweight `GET` calls to track long-running pipeline execution, mapping changes natively to active HTML nodes.
