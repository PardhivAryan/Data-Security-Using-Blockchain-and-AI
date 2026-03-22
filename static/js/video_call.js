window.VideoCall = (() => {
  let pc = null;
  let ws = null;
  let localStream = null;
  let remoteStream = null;
  let statusCb = null;
  let pendingIceCandidates = [];
  let currentRoomId = "";

  const status = (message) => {
    if (typeof statusCb === "function") statusCb(message);
  };

  function wsUrl(roomId) {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const token = localStorage.getItem("token") || "";
    return `${proto}://${location.host}/api/video/ws/${encodeURIComponent(roomId)}?token=${encodeURIComponent(token)}`;
  }

  function getAuthHeaders() {
    const token = localStorage.getItem("token") || "";
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  async function waitForWsOpen(socket) {
    if (socket.readyState === WebSocket.OPEN) return;

    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("WebSocket connection timed out"));
      }, 10000);

      socket.addEventListener("open", () => {
        clearTimeout(timeout);
        resolve();
      }, { once: true });

      socket.addEventListener("error", () => {
        clearTimeout(timeout);
        reject(new Error("Signaling connection failed"));
      }, { once: true });

      socket.addEventListener("close", (ev) => {
        clearTimeout(timeout);
        reject(new Error(`Signaling closed (${ev.code})`));
      }, { once: true });
    });
  }

  function safePlay(videoEl) {
    if (!videoEl) return;
    const maybePromise = videoEl.play?.();
    if (maybePromise && typeof maybePromise.catch === "function") {
      maybePromise.catch(() => {});
    }
  }

  async function flushPendingIce() {
    if (!pc || !pc.remoteDescription) return;

    while (pendingIceCandidates.length > 0) {
      const candidate = pendingIceCandidates.shift();
      try {
        await pc.addIceCandidate(candidate);
      } catch {}
    }
  }

  async function setupPeer(localVideo, remoteVideo) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error("Camera and microphone are not supported in this browser.");
    }

    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    localVideo.srcObject = localStream;
    localVideo.muted = true;
    safePlay(localVideo);

    remoteStream = new MediaStream();
    remoteVideo.srcObject = remoteStream;
    safePlay(remoteVideo);

    pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });

    localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));

    pc.ontrack = (ev) => {
      ev.streams.forEach((stream) => {
        stream.getTracks().forEach((track) => {
          const alreadyPresent = remoteStream.getTracks().some((t) => t.id === track.id);
          if (!alreadyPresent) remoteStream.addTrack(track);
        });
      });
      safePlay(remoteVideo);
      status("Remote media received.");
    };

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        send({ type: "ice", candidate: ev.candidate });
      }
    };

    pc.oniceconnectionstatechange = () => {
      const state = pc?.iceConnectionState;
      if (state === "connected" || state === "completed") status("Video call connected.");
      if (state === "failed") status("ICE connection failed. Try rejoining.");
      if (state === "disconnected") status("Peer disconnected.");
    };

    pc.onconnectionstatechange = () => {
      const state = pc?.connectionState;
      if (state === "connected") status("Peer connection established.");
      if (state === "failed") status("Peer connection failed.");
      if (state === "closed") status("Call closed.");
    };
  }

  async function join(roomId, localVideo, remoteVideo, cb) {
    statusCb = cb;

    if (!roomId) throw new Error("Room ID is required.");
    if (!localStorage.getItem("token")) throw new Error("Login required. Token is missing.");

    if (pc || ws || localStream) {
      hangup();
    }

    currentRoomId = roomId;
    pendingIceCandidates = [];

    status("Requesting camera and microphone...");
    await setupPeer(localVideo, remoteVideo);

    status("Connecting to signaling server...");
    ws = new WebSocket(wsUrl(roomId));

    ws.onmessage = async (ev) => {
      const msg = JSON.parse(ev.data);

      if (msg.type === "offer") {
        status("Offer received. Creating answer...");
        await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        await flushPendingIce();
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        send({ type: "answer", sdp: pc.localDescription });
        status("Answer sent. Waiting for media...");
        return;
      }

      if (msg.type === "answer") {
        status("Answer received. Finalizing connection...");
        await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        await flushPendingIce();
        status("Answer applied. Waiting for media...");
        return;
      }

      if (msg.type === "ice" && msg.candidate) {
        const candidate = new RTCIceCandidate(msg.candidate);
        if (pc.remoteDescription) {
          try {
            await pc.addIceCandidate(candidate);
          } catch {}
        } else {
          pendingIceCandidates.push(candidate);
        }
        return;
      }

      if (msg.type === "hangup" || msg.type === "peer_left") {
        status("Other participant left the call.");
        cleanup(false);
      }
    };

    ws.onerror = () => {
      status("Signaling connection error.");
    };

    ws.onclose = (ev) => {
      if (ev.code === 4401) status("Unauthorized video room access. Please login again.");
      else if (ev.code === 4403) status("You are not allowed to join this room.");
      else if (ev.code === 4404) status("Room not found or inactive.");
      else status("Signaling connection closed.");
    };

    await waitForWsOpen(ws);
    status("Joined room successfully.");
  }

  function send(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  }

  async function startCaller(cb) {
    statusCb = cb || statusCb;
    if (!pc) throw new Error("Join the room first.");
    if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error("Signaling server is not connected yet.");

    status("Creating WebRTC offer...");
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    send({ type: "offer", sdp: pc.localDescription });
    status("Offer sent. Waiting for patient answer...");
  }

  function cleanup(updateStatus = true) {
    try {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    } catch {}

    try {
      if (pc) {
        pc.ontrack = null;
        pc.onicecandidate = null;
        pc.oniceconnectionstatechange = null;
        pc.onconnectionstatechange = null;
        pc.close();
      }
    } catch {}

    ws = null;
    pc = null;
    pendingIceCandidates = [];
    currentRoomId = "";

    if (localStream) {
      localStream.getTracks().forEach((track) => track.stop());
    }
    localStream = null;

    if (remoteStream) {
      remoteStream.getTracks().forEach((track) => track.stop());
    }
    remoteStream = null;

    if (updateStatus) {
      status("Call ended.");
    }
  }

  function hangup(cb) {
    statusCb = cb || statusCb;
    try {
      send({ type: "hangup" });
    } catch {}
    cleanup(true);
  }

  async function createRoom(patientId) {
    const token = localStorage.getItem("token") || "";
    if (!token) throw new Error("Login required. Token is missing.");
    if (!patientId) throw new Error("Patient ID is required.");

    const res = await fetch(`${window.location.origin}/api/video/sessions?patient_id=${encodeURIComponent(patientId)}`, {
      method: "POST",
      headers: {
        ...getAuthHeaders(),
        Accept: "application/json",
      },
    });

    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!res.ok) {
      const detail = data && data.detail ? data.detail : (typeof data === "string" ? data : "Failed to create room");
      throw new Error(String(detail));
    }

    if (!data || !data.room_id) {
      throw new Error("Room ID was not returned by the server.");
    }

    currentRoomId = data.room_id;
    return data.room_id;
  }

  function initPageBindings() {
    const localVideo = document.getElementById("localVideo");
    const remoteVideo = document.getElementById("remoteVideo");
    if (!localVideo || !remoteVideo) return;

    const createRoomBtn = document.getElementById("createRoomBtn");
    const joinRoomBtn = document.getElementById("joinRoomBtn");
    const startCallBtn = document.getElementById("startCallBtn");
    const hangupBtn = document.getElementById("hangupBtn");
    const patientIdInput = document.getElementById("patientId");
    const roomIdInput = document.getElementById("roomId");
    const roomIdDisplay = document.getElementById("roomIdDisplay");

    let statusBox = document.getElementById("videoCallStatus");
    if (!statusBox) {
      statusBox = document.createElement("div");
      statusBox.id = "videoCallStatus";
      statusBox.style.marginTop = "12px";
      statusBox.style.padding = "10px";
      statusBox.style.borderRadius = "8px";
      statusBox.style.background = "#eef6ff";
      statusBox.style.color = "#0f172a";
      statusBox.style.fontWeight = "600";

      const hostCard =
        createRoomBtn?.closest(".card") ||
        joinRoomBtn?.closest(".card") ||
        localVideo.parentElement?.parentElement;

      if (hostCard) hostCard.appendChild(statusBox);
    }

    const showStatus = (message) => {
      if (statusBox) statusBox.textContent = message;
    };

    const resolveRoomId = () => {
      const fromInput = roomIdInput?.value?.trim();
      if (fromInput) return fromInput;
      const fromDisplay = roomIdDisplay?.textContent?.trim();
      if (fromDisplay) return fromDisplay;
      return currentRoomId || "";
    };

    if (createRoomBtn) {
      createRoomBtn.addEventListener("click", async () => {
        try {
          const patientId = patientIdInput?.value?.trim() || "";
          showStatus("Creating room...");
          const roomId = await createRoom(patientId);
          if (roomIdDisplay) roomIdDisplay.textContent = roomId;
          if (roomIdInput) roomIdInput.value = roomId;
          showStatus("Room created. Share this Room ID with the patient.");
        } catch (err) {
          showStatus(err?.message || "Failed to create room.");
        }
      });
    }

    if (joinRoomBtn) {
      joinRoomBtn.addEventListener("click", async () => {
        try {
          const roomId = resolveRoomId();
          showStatus("Joining room...");
          await join(roomId, localVideo, remoteVideo, showStatus);
        } catch (err) {
          showStatus(err?.message || "Failed to join room.");
        }
      });
    }

    if (startCallBtn) {
      startCallBtn.addEventListener("click", async () => {
        try {
          await startCaller(showStatus);
        } catch (err) {
          showStatus(err?.message || "Failed to start call.");
        }
      });
    }

    if (hangupBtn) {
      hangupBtn.addEventListener("click", () => {
        hangup(showStatus);
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPageBindings);
  } else {
    initPageBindings();
  }

  return { join, startCaller, hangup, createRoom };
})();