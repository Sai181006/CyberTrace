/* Interactive perspective view of the same paged graph shown in the SVG view. */
(function () {
  "use strict";

  function createCyberTraceGraph3D(canvas, onNeighbor, onCenter) {
    const context = canvas.getContext("2d");
    if (!context) return null;

    const view = { yaw: 0.6, pitch: -0.25, distance: 6.5 };
    let graph = null;
    let projectedNodes = [];
    let dragging = null;
    let hovered = -2;
    let pendingFrame = false;

    function title(properties) {
      return properties.name || properties.address || properties.cve_id || properties.source_id || "Entity";
    }

    function layout(count) {
      const goldenAngle = Math.PI * (3 - Math.sqrt(5));
      return Array.from({ length: count }, (_, index) => {
        const height = 1 - (2 * (index + 0.5)) / count;
        const circle = Math.sqrt(1 - height * height);
        const angle = index * goldenAngle;
        return { x: Math.cos(angle) * circle * 2.1, y: height * 1.7, z: Math.sin(angle) * circle * 2.1 };
      });
    }

    function project(point, width, height) {
      const cy = Math.cos(view.yaw), sy = Math.sin(view.yaw);
      const cp = Math.cos(view.pitch), sp = Math.sin(view.pitch);
      const rotatedX = point.x * cy - point.z * sy;
      const rotatedZ = point.x * sy + point.z * cy;
      const rotatedY = point.y * cp - rotatedZ * sp;
      const depth = view.distance - (point.y * sp + rotatedZ * cp);
      const scale = Math.min(width * 0.88, 640) / Math.max(depth, 0.8);
      return { x: width / 2 + rotatedX * scale, y: height / 2 - rotatedY * scale, depth, scale };
    }

    function line(start, end, color, width) {
      context.beginPath();
      context.moveTo(start.x, start.y);
      context.lineTo(end.x, end.y);
      context.strokeStyle = color;
      context.lineWidth = width;
      context.stroke();
    }

    function render() {
      if (canvas.hidden) return;
      const bounds = canvas.getBoundingClientRect();
      const width = Math.max(1, bounds.width);
      const height = Math.max(1, bounds.height);
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const pixelWidth = Math.round(width * ratio);
      const pixelHeight = Math.round(height * ratio);
      if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
        canvas.width = pixelWidth;
        canvas.height = pixelHeight;
      }
      context.setTransform(ratio, 0, 0, ratio, 0, 0);

      const background = context.createRadialGradient(width / 2, height / 2, 30, width / 2, height / 2, width * 0.7);
      background.addColorStop(0, "#173343");
      background.addColorStop(1, "#07131e");
      context.fillStyle = background;
      context.fillRect(0, 0, width, height);

      // A receding ground grid makes rotation and depth easier to read.
      for (let grid = -3; grid <= 3; grid += 1) {
        line(project({ x: grid, y: -1.9, z: -3 }, width, height), project({ x: grid, y: -1.9, z: 3 }, width, height), "#31506466", 1);
        line(project({ x: -3, y: -1.9, z: grid }, width, height), project({ x: 3, y: -1.9, z: grid }, width, height), "#31506466", 1);
      }

      if (!graph) {
        context.fillStyle = "#a9c1cb";
        context.font = "15px Segoe UI, sans-serif";
        context.textAlign = "center";
        context.fillText("Press Explore to load the 3D graph", width / 2, height / 2);
        projectedNodes = [];
        return;
      }

      const center = project({ x: 0, y: 0, z: 0 }, width, height);
      const positions = layout(graph.neighbors.length);
      projectedNodes = positions.map((point, index) => {
        const projected = project(point, width, height);
        return { ...projected, index, radius: Math.max(8, Math.min(18, projected.scale * 0.16)) };
      });
      const farToNear = [...projectedNodes].sort((a, b) => b.depth - a.depth);

      farToNear.forEach(node => {
        const relationship = graph.relationships[node.index];
        const synthetic = relationship.properties.is_synthetic;
        line(center, node, synthetic ? "#ffc857a0" : "#3edbd2b0", Math.max(1, 2.5 * (6 / node.depth)));
      });

      const nodes = [...farToNear, { ...center, index: -1, radius: 22 }].sort((a, b) => b.depth - a.depth);
      nodes.forEach(node => {
        const isCenter = node.index === -1;
        const properties = isCenter ? graph.center : graph.neighbors[node.index].properties;
        const synthetic = Boolean(properties.is_synthetic);
        const active = hovered === node.index;
        context.beginPath();
        context.arc(node.x, node.y, node.radius + (active ? 3 : 0), 0, Math.PI * 2);
        context.fillStyle = isCenter ? "#124d54" : synthetic ? "#6b4d1e" : "#193b61";
        context.fill();
        context.lineWidth = active ? 4 : 2.5;
        context.strokeStyle = isCenter ? "#3edbd2" : synthetic ? "#ffc857" : "#55a7ff";
        context.stroke();

        if (isCenter || graph.neighbors.length <= 18 || active) {
          const label = title(properties).slice(0, 22);
          context.font = isCenter ? "bold 13px Segoe UI, sans-serif" : "12px Segoe UI, sans-serif";
          context.textAlign = "center";
          context.textBaseline = "top";
          context.lineWidth = 4;
          context.strokeStyle = "#07131e";
          context.strokeText(label, node.x, node.y + node.radius + 7);
          context.fillStyle = "#ecf6f8";
          context.fillText(label, node.x, node.y + node.radius + 7);
        }
      });

      context.font = "12px Segoe UI, sans-serif";
      context.textAlign = "left";
      context.fillStyle = "#a9c1cb";
      context.fillText(`${graph.neighbors.length} visible connections · ${graph.total} matching`, 16, 24);
      context.fillStyle = "#3edbd2";
      context.fillText("● sourced link", 16, height - 36);
      context.fillStyle = "#ffc857";
      context.fillText("● synthetic link", 16, height - 17);
    }

    function requestRender() {
      if (pendingFrame) return;
      pendingFrame = true;
      requestAnimationFrame(() => { pendingFrame = false; render(); });
    }

    function pointFromEvent(event) {
      const bounds = canvas.getBoundingClientRect();
      return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
    }

    function hitTest(point) {
      const candidates = [...projectedNodes, { x: canvas.clientWidth / 2, y: canvas.clientHeight / 2, index: -1, radius: 22 }];
      return candidates
        .filter(node => Math.hypot(node.x - point.x, node.y - point.y) <= node.radius + 7)
        .sort((a, b) => Math.hypot(a.x - point.x, a.y - point.y) - Math.hypot(b.x - point.x, b.y - point.y))[0]?.index ?? -2;
    }

    canvas.addEventListener("pointerdown", event => {
      if (!graph) return;
      const point = pointFromEvent(event);
      dragging = { id: event.pointerId, x: point.x, y: point.y, lastX: point.x, lastY: point.y, moved: false };
      canvas.setPointerCapture(event.pointerId);
    });
    canvas.addEventListener("pointermove", event => {
      const point = pointFromEvent(event);
      if (dragging && dragging.id === event.pointerId) {
        if (Math.hypot(point.x - dragging.x, point.y - dragging.y) > 5) dragging.moved = true;
        view.yaw += (point.x - dragging.lastX) * 0.008;
        view.pitch = Math.max(-1.3, Math.min(1.3, view.pitch + (point.y - dragging.lastY) * 0.008));
        dragging.lastX = point.x;
        dragging.lastY = point.y;
        requestRender();
      } else {
        const next = hitTest(point);
        if (next !== hovered) { hovered = next; canvas.style.cursor = next === -2 ? "grab" : "pointer"; requestRender(); }
      }
    });
    canvas.addEventListener("pointerup", event => {
      if (!dragging || dragging.id !== event.pointerId) return;
      const moved = dragging.moved;
      dragging = null;
      if (moved) return;
      const index = hitTest(pointFromEvent(event));
      if (index === -1) onCenter(graph);
      else if (index >= 0) onNeighbor(graph.neighbors[index]);
    });
    canvas.addEventListener("pointercancel", () => { dragging = null; });
    canvas.addEventListener("pointerleave", () => { if (!dragging) { hovered = -2; requestRender(); } });
    canvas.addEventListener("wheel", event => {
      event.preventDefault();
      view.distance = Math.max(3.4, Math.min(11, view.distance * (event.deltaY > 0 ? 1.1 : 0.9)));
      requestRender();
    }, { passive: false });
    canvas.addEventListener("keydown", event => {
      if (event.key === "ArrowLeft") view.yaw -= 0.16;
      else if (event.key === "ArrowRight") view.yaw += 0.16;
      else if (event.key === "ArrowUp") view.pitch = Math.max(-1.3, view.pitch - 0.16);
      else if (event.key === "ArrowDown") view.pitch = Math.min(1.3, view.pitch + 0.16);
      else if (event.key === "+" || event.key === "=") view.distance = Math.max(3.4, view.distance / 1.2);
      else if (event.key === "-") view.distance = Math.min(11, view.distance * 1.2);
      else return;
      event.preventDefault();
      requestRender();
    });
    window.addEventListener("resize", requestRender);

    return {
      render(data) { graph = data; requestRender(); },
      show() { requestRender(); },
      zoomIn() { view.distance = Math.max(3.4, view.distance / 1.25); requestRender(); },
      zoomOut() { view.distance = Math.min(11, view.distance * 1.25); requestRender(); },
      reset() { view.yaw = 0.6; view.pitch = -0.25; view.distance = 6.5; requestRender(); },
    };
  }

  window.createCyberTraceGraph3D = createCyberTraceGraph3D;
})();
