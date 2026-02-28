import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react';
import clsx from 'clsx';
import dayjs from 'dayjs';
import {
  ArrowLeft,
  Check,
  CheckCheck,
  CirclePlus,
  Edit3,
  Image as ImageIcon,
  KeyRound,
  LogOut,
  Mic,
  Paperclip,
  Phone,
  Pin,
  Search,
  SendHorizontal,
  Shield,
  Smile,
  Trash2,
  Users,
  Video,
  X,
} from 'lucide-react';

import { useAuth } from '../context/useAuth';
import { decryptText, encryptText } from '../lib/crypto';
import { api } from '../lib/api';
import { connectSocket, disconnectSocket, getSocket } from '../lib/socket';
import type { Chat, Message, StatusItem, User } from '../types';

const REACTION_CHOICES = ['??', '??', '??', '??', '??', '??'];
const ENCRYPTED_PLACEHOLDER = '__encrypted__';
const ENCRYPTION_FAIL = '__decrypt_fail__';

type CallMode = 'audio' | 'video';

type CallSession = {
  callId: string;
  chatId: string;
  type: CallMode;
  peerId: string;
  peerName: string;
  status: 'incoming' | 'outgoing' | 'active';
};

type IncomingCall = {
  callId: string;
  chatId: string;
  type: CallMode;
  callerId: string;
  callerName: string;
};

function getInitials(name: string) {
  return name
    .split(' ')
    .map((part) => part[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();
}

function formatChatTime(value?: string | null) {
  if (!value) {
    return '';
  }

  const date = dayjs(value);
  if (date.isSame(dayjs(), 'day')) {
    return date.format('HH:mm');
  }

  if (date.isSame(dayjs(), 'year')) {
    return date.format('DD MMM');
  }

  return date.format('DD/MM/YY');
}

function formatMessageTime(value: string) {
  return dayjs(value).format('HH:mm');
}

function summarizeMessage(message: Message | null) {
  if (!message) {
    return 'Start chatting';
  }

  if (message.isDeleted) {
    return 'Message deleted';
  }

  if (message.encryption) {
    return 'Encrypted message';
  }

  if (!message.text && message.attachments.length > 0) {
    return message.attachments.length === 1 ? 'Attachment' : `${message.attachments.length} attachments`;
  }

  if (message.text && message.attachments.length > 0) {
    return `${message.text} (${message.attachments.length} files)`;
  }

  return message.text;
}

function apiErrorMessage(error: unknown) {
  if (typeof error === 'object' && error && 'response' in error) {
    const response = (error as { response?: { data?: { message?: string } } }).response;
    if (response?.data?.message) {
      return response.data.message;
    }
  }

  return error instanceof Error ? error.message : 'Operation failed.';
}

function Avatar({ label, color, size = 42 }: { label: string; color: string; size?: number }) {
  return (
    <span
      className="avatar"
      style={{
        backgroundColor: color,
        width: `${size}px`,
        height: `${size}px`,
        minWidth: `${size}px`,
      }}
    >
      {getInitials(label)}
    </span>
  );
}

function sortChats(items: Chat[]) {
  return [...items].sort(
    (a, b) => +new Date(b.lastMessageAt ?? b.updatedAt) - +new Date(a.lastMessageAt ?? a.updatedAt),
  );
}

function keyForChat(chatId: string) {
  return `chatwave-e2ee:${chatId}`;
}

export function ChatScreen() {
  const { user, token, logout, updateProfile } = useAuth();

  const [chats, setChats] = useState<Chat[]>([]);
  const [messagesByChat, setMessagesByChat] = useState<Record<string, Message[]>>({});
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [chatFilter, setChatFilter] = useState('');
  const [loadingChats, setLoadingChats] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);

  const [composer, setComposer] = useState('');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [encryptOutgoing, setEncryptOutgoing] = useState(false);

  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState<User[]>([]);
  const [directoryUsers, setDirectoryUsers] = useState<User[]>([]);

  const [showGroupModal, setShowGroupModal] = useState(false);
  const [groupName, setGroupName] = useState('');
  const [groupDescription, setGroupDescription] = useState('');
  const [groupMemberIds, setGroupMemberIds] = useState<string[]>([]);

  const [onlineUserIds, setOnlineUserIds] = useState<Set<string>>(new Set());
  const [typingByChat, setTypingByChat] = useState<Record<string, string[]>>({});

  const [mobileView, setMobileView] = useState<'list' | 'chat'>('list');

  const [profileName, setProfileName] = useState('');
  const [profileAbout, setProfileAbout] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);

  const [chatKeys, setChatKeys] = useState<Record<string, string>>({});
  const [decryptedMap, setDecryptedMap] = useState<Record<string, string>>({});

  const [pinsByChat, setPinsByChat] = useState<Record<string, Message[]>>({});
  const [showPinned, setShowPinned] = useState(true);

  const [statuses, setStatuses] = useState<StatusItem[]>([]);
  const [showStatusComposer, setShowStatusComposer] = useState(false);
  const [statusText, setStatusText] = useState('');
  const [statusFile, setStatusFile] = useState<File | null>(null);
  const [viewingStatus, setViewingStatus] = useState<StatusItem | null>(null);

  const [incomingCall, setIncomingCall] = useState<IncomingCall | null>(null);
  const [callSession, setCallSession] = useState<CallSession | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);

  const [errorText, setErrorText] = useState<string | null>(null);

  const listRef = useRef<HTMLDivElement | null>(null);
  const typingTimerRef = useRef<number | null>(null);
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null);
  const callSessionRef = useRef<CallSession | null>(null);
  const activeChatIdRef = useRef<string | null>(null);
  const pendingCandidatesRef = useRef<Record<string, RTCIceCandidateInit[]>>({});

  const activeChat = useMemo(
    () => chats.find((chat) => chat.id === activeChatId) ?? null,
    [activeChatId, chats],
  );

  const activeMessages = useMemo(() => {
    if (!activeChatId) {
      return [];
    }
    return messagesByChat[activeChatId] ?? [];
  }, [activeChatId, messagesByChat]);

  const filteredChats = useMemo(() => {
    const query = chatFilter.trim().toLowerCase();
    if (!query) {
      return chats;
    }

    return chats.filter((chat) => {
      const inTitle = chat.title.toLowerCase().includes(query);
      const inPreview = summarizeMessage(chat.lastMessage).toLowerCase().includes(query);
      return inTitle || inPreview;
    });
  }, [chatFilter, chats]);

  const typingNames = useMemo(() => {
    if (!activeChatId || !activeChat) {
      return [];
    }

    const typingIds = typingByChat[activeChatId] ?? [];
    return activeChat.members.filter((member) => typingIds.includes(member.id)).map((member) => member.name);
  }, [activeChat, activeChatId, typingByChat]);

  const typingLabel =
    typingNames.length === 0
      ? ''
      : typingNames.length === 1
        ? `${typingNames[0]} is typing...`
        : `${typingNames.slice(0, 2).join(', ')} are typing...`;

  const activeKey = activeChatId ? chatKeys[activeChatId] ?? '' : '';
  const activePins = activeChatId ? pinsByChat[activeChatId] ?? [] : [];

  const statusCards = useMemo(() => {
    const byUser = new Map<string, StatusItem>();
    statuses.forEach((status) => {
      const existing = byUser.get(status.userId);
      if (!existing || +new Date(status.createdAt) > +new Date(existing.createdAt)) {
        byUser.set(status.userId, status);
      }
    });

    return [...byUser.values()].sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt));
  }, [statuses]);

  const isPeerOnline = useMemo(() => {
    if (!activeChat || !activeChat.directPeer) {
      return false;
    }

    return onlineUserIds.has(activeChat.directPeer.id);
  }, [activeChat, onlineUserIds]);

  const updateMessageInState = useCallback(
    (chatId: string, messageId: string, updater: (message: Message) => Message) => {
      setMessagesByChat((previous) => ({
        ...previous,
        [chatId]: (previous[chatId] ?? []).map((message) =>
          message.id === messageId ? updater(message) : message,
        ),
      }));
    },
    [],
  );

  const fetchChats = useCallback(async () => {
    const { data } = await api.get<{ chats: Chat[] }>('/chats');
    const sorted = sortChats(data.chats);
    setChats(sorted);
    setActiveChatId((current) => {
      if (current && sorted.some((chat) => chat.id === current)) {
        return current;
      }
      return sorted[0]?.id ?? null;
    });
  }, []);

  const fetchDirectory = useCallback(async () => {
    const { data } = await api.get<{ users: User[] }>('/users/search');
    setDirectoryUsers(data.users);
  }, []);

  const fetchStatuses = useCallback(async () => {
    const { data } = await api.get<{ statuses: StatusItem[] }>('/statuses');
    setStatuses(data.statuses);
  }, []);

  const fetchPins = useCallback(async (chatId: string) => {
    const { data } = await api.get<{ messages: Message[] }>(`/chats/${chatId}/pins`);
    setPinsByChat((previous) => ({
      ...previous,
      [chatId]: data.messages,
    }));
  }, []);

  const markChatAsRead = useCallback(
    async (chatId: string) => {
      try {
        await api.post(`/chats/${chatId}/read`);
        getSocket()?.emit('chat:read', { chatId });

        if (!user) {
          return;
        }

        setChats((previous) =>
          previous.map((chat) => (chat.id === chatId ? { ...chat, unreadCount: 0 } : chat)),
        );

        setMessagesByChat((previous) => {
          const chatMessages = previous[chatId] ?? [];
          const seenAt = new Date().toISOString();
          const nextMessages = chatMessages.map((message) => {
            if (message.senderId === user.id || message.seenBy.some((entry) => entry.userId === user.id)) {
              return message;
            }

            return {
              ...message,
              seenBy: [...message.seenBy, { userId: user.id, at: seenAt }],
            };
          });

          return {
            ...previous,
            [chatId]: nextMessages,
          };
        });
      } catch {
        // Ignore transient read sync failures.
      }
    },
    [user],
  );

  const fetchMessages = useCallback(async (chatId: string) => {
    setLoadingMessages(true);
    try {
      const { data } = await api.get<{ messages: Message[] }>(`/chats/${chatId}/messages`, {
        params: { limit: 80 },
      });
      setMessagesByChat((previous) => ({
        ...previous,
        [chatId]: data.messages,
      }));
    } finally {
      setLoadingMessages(false);
    }
  }, []);

  const flushPendingCandidates = useCallback(async (peer: RTCPeerConnection, callId: string) => {
    const queued = pendingCandidatesRef.current[callId] ?? [];
    if (queued.length === 0) {
      return;
    }

    for (const candidate of queued) {
      try {
        await peer.addIceCandidate(new RTCIceCandidate(candidate));
      } catch {
        // Ignore broken candidate packets.
      }
    }

    delete pendingCandidatesRef.current[callId];
  }, []);

  const cleanupCallMedia = useCallback(() => {
    peerRef.current?.close();
    peerRef.current = null;
    pendingCandidatesRef.current = {};

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }

    setLocalStream(null);
    setRemoteStream(null);
  }, []);

  const endCallLocally = useCallback(() => {
    cleanupCallMedia();
    setIncomingCall(null);
    setCallSession(null);
  }, [cleanupCallMedia]);

  const ensurePeerConnection = useCallback(
    (callId: string, targetUserId: string) => {
      if (peerRef.current) {
        return peerRef.current;
      }

      const peer = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      });

      const stream = localStreamRef.current;
      if (stream) {
        stream.getTracks().forEach((track) => peer.addTrack(track, stream));
      }

      peer.ontrack = (event) => {
        const [streamFromEvent] = event.streams;
        if (streamFromEvent) {
          setRemoteStream(streamFromEvent);
          return;
        }

        // Safari can deliver tracks without prebuilt stream objects.
        setRemoteStream((previous) => {
          const stream = previous ?? new MediaStream();
          stream.addTrack(event.track);
          return stream;
        });
      };

      peer.onicecandidate = (event) => {
        if (!event.candidate) {
          return;
        }

        getSocket()?.emit('webrtc:signal', {
          callId,
          targetUserId,
          signal: {
            type: 'candidate',
            candidate: event.candidate,
          },
        });
      };

      peerRef.current = peer;
      return peer;
    },
    [],
  );

  const getDisplayText = useCallback(
    (message: Message) => {
      if (message.isDeleted) {
        return 'This message was deleted.';
      }

      if (!message.encryption) {
        return message.text;
      }

      const value = decryptedMap[message.id];
      if (!value || value === ENCRYPTED_PLACEHOLDER) {
        return 'Encrypted message. Set chat key to decrypt.';
      }

      if (value === ENCRYPTION_FAIL) {
        return 'Unable to decrypt this message with your current key.';
      }

      return value;
    },
    [decryptedMap],
  );

  useEffect(() => {
    if (!user) {
      return;
    }

    setProfileName(user.name);
    setProfileAbout(user.about);
  }, [user]);

  useEffect(() => {
    let mounted = true;

    async function bootstrap() {
      setLoadingChats(true);
      setErrorText(null);

      try {
        await Promise.all([fetchChats(), fetchDirectory(), fetchStatuses()]);
      } catch (error) {
        if (mounted) {
          setErrorText(apiErrorMessage(error));
        }
      } finally {
        if (mounted) {
          setLoadingChats(false);
        }
      }
    }

    void bootstrap();

    return () => {
      mounted = false;
    };
  }, [fetchChats, fetchDirectory, fetchStatuses]);

  useEffect(() => {
    if (!activeChatId) {
      return;
    }

    const cached = localStorage.getItem(keyForChat(activeChatId));
    if (cached) {
      setChatKeys((previous) => ({
        ...previous,
        [activeChatId]: cached,
      }));
      setEncryptOutgoing(true);
    } else {
      setEncryptOutgoing(false);
    }
  }, [activeChatId]);

  useEffect(() => {
    if (!activeChatId) {
      return;
    }

    getSocket()?.emit('chat:join', { chatId: activeChatId });

    if (!messagesByChat[activeChatId]) {
      void fetchMessages(activeChatId).then(() => {
        void markChatAsRead(activeChatId);
      });
    } else {
      void markChatAsRead(activeChatId);
    }

    void fetchPins(activeChatId);
  }, [activeChatId, fetchMessages, fetchPins, markChatAsRead, messagesByChat]);

  useEffect(() => {
    if (!listRef.current) {
      return;
    }

    listRef.current.scrollTo({
      top: listRef.current.scrollHeight,
      behavior: 'smooth',
    });
  }, [activeChatId, activeMessages.length]);

  useEffect(() => {
    if (!activeChatId) {
      return;
    }

    const chatId = activeChatId;
    const encryptedMessages = activeMessages.filter((message) => message.encryption && !message.isDeleted);
    if (encryptedMessages.length === 0) {
      return;
    }

    let cancelled = false;

    async function run() {
      const nextEntries: Record<string, string> = {};

      for (const message of encryptedMessages) {
        if (!activeKey) {
          nextEntries[message.id] = ENCRYPTED_PLACEHOLDER;
          continue;
        }

        try {
          const plainText = await decryptText(message.text, message.encryption!.iv, activeKey, chatId);
          nextEntries[message.id] = plainText;
        } catch {
          nextEntries[message.id] = ENCRYPTION_FAIL;
        }
      }

      if (!cancelled) {
        setDecryptedMap((previous) => ({
          ...previous,
          ...nextEntries,
        }));
      }
    }

    void run();

    return () => {
      cancelled = true;
    };
  }, [activeChatId, activeKey, activeMessages]);

  useEffect(() => {
    if (!localVideoRef.current) {
      return;
    }

    if (!localStream) {
      localVideoRef.current.srcObject = null;
      return;
    }

    localVideoRef.current.srcObject = localStream;
    void localVideoRef.current.play().catch(() => {
      // Autoplay can fail silently on some browsers until user gesture.
    });
  }, [callSession, localStream]);

  useEffect(() => {
    if (callSession?.type === 'video' && remoteVideoRef.current) {
      if (!remoteStream) {
        remoteVideoRef.current.srcObject = null;
      } else {
        remoteVideoRef.current.srcObject = remoteStream;
        void remoteVideoRef.current.play().catch(() => {
          // Autoplay can fail silently on some browsers until user gesture.
        });
      }
    }

    if (callSession?.type === 'audio' && remoteAudioRef.current) {
      if (!remoteStream) {
        remoteAudioRef.current.srcObject = null;
      } else {
        remoteAudioRef.current.srcObject = remoteStream;
        void remoteAudioRef.current.play().catch(() => {
          // Autoplay can fail silently on some browsers until user gesture.
        });
      }
    }

    if (callSession?.type === 'video' && remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null;
    }
  }, [callSession, remoteStream]);

  useEffect(() => {
    callSessionRef.current = callSession;
  }, [callSession]);

  useEffect(() => {
    activeChatIdRef.current = activeChatId;
  }, [activeChatId]);

  useEffect(() => {
    if (!token || !user) {
      return;
    }

    const socket = connectSocket(token);

    const handlePresence = ({ userIds }: { userIds: string[] }) => {
      setOnlineUserIds(new Set(userIds));
    };

    const handleChatList = () => {
      void fetchChats();
    };

    const handleStatusNew = ({ status }: { status: StatusItem }) => {
      setStatuses((previous) => {
        const next = [status, ...previous.filter((entry) => entry.id !== status.id)];
        return next.sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt));
      });
    };

    const handleMessageNew = ({ chatId, message }: { chatId: string; message: Message }) => {
      setMessagesByChat((previous) => {
        const existing = previous[chatId] ?? [];
        if (existing.some((entry) => entry.id === message.id)) {
          return previous;
        }

        return {
          ...previous,
          [chatId]: [...existing, message],
        };
      });

      setChats((previous) => {
        const next = previous.map((chat) => {
          if (chat.id !== chatId) {
            return chat;
          }

          const currentActiveChatId = activeChatIdRef.current;
          const unreadCount =
            chatId === currentActiveChatId || message.senderId === user.id ? 0 : chat.unreadCount + 1;

          return {
            ...chat,
            lastMessage: message,
            lastMessageAt: message.createdAt,
            unreadCount,
          };
        });

        return sortChats(next);
      });

      if (chatId === activeChatIdRef.current) {
        void markChatAsRead(chatId);
      }
    };

    const handleMessageUpdated = ({ chatId, message }: { chatId: string; message: Message }) => {
      setMessagesByChat((previous) => ({
        ...previous,
        [chatId]: (previous[chatId] ?? []).map((entry) => (entry.id === message.id ? message : entry)),
      }));

      setChats((previous) =>
        previous.map((chat) =>
          chat.id === chatId && chat.lastMessage?.id === message.id ? { ...chat, lastMessage: message } : chat,
        ),
      );
    };

    const handleMessageDeleted = ({
      chatId,
      messageId,
    }: {
      chatId: string;
      messageId: string;
    }) => {
      updateMessageInState(chatId, messageId, (message) => ({
        ...message,
        text: '',
        isDeleted: true,
        attachments: [],
        reactions: [],
        pinnedAt: null,
        pinnedBy: [],
      }));

      setPinsByChat((previous) => ({
        ...previous,
        [chatId]: (previous[chatId] ?? []).filter((message) => message.id !== messageId),
      }));

      setChats((previous) =>
        previous.map((chat) =>
          chat.id === chatId && chat.lastMessage?.id === messageId
            ? {
                ...chat,
                lastMessage: {
                  ...chat.lastMessage,
                  text: '',
                  isDeleted: true,
                  attachments: [],
                },
              }
            : chat,
        ),
      );
    };

    const handleMessageSeen = ({
      chatId,
      userId,
      messageIds,
      seenAt,
    }: {
      chatId: string;
      userId: string;
      messageIds: string[];
      seenAt: string;
    }) => {
      setMessagesByChat((previous) => ({
        ...previous,
        [chatId]: (previous[chatId] ?? []).map((message) => {
          if (!messageIds.includes(message.id)) {
            return message;
          }

          const alreadySeen = message.seenBy.some((entry) => entry.userId === userId);
          if (alreadySeen) {
            return message;
          }

          return {
            ...message,
            seenBy: [...message.seenBy, { userId, at: seenAt }],
          };
        }),
      }));

      if (userId === user.id) {
        setChats((previous) =>
          previous.map((chat) => (chat.id === chatId ? { ...chat, unreadCount: 0 } : chat)),
        );
      }
    };

    const handleTyping = ({
      chatId,
      userId,
      isTyping,
    }: {
      chatId: string;
      userId: string;
      isTyping: boolean;
    }) => {
      if (userId === user.id) {
        return;
      }

      setTypingByChat((previous) => {
        const existingIds = new Set(previous[chatId] ?? []);

        if (isTyping) {
          existingIds.add(userId);
        } else {
          existingIds.delete(userId);
        }

        return {
          ...previous,
          [chatId]: [...existingIds],
        };
      });
    };

    const handleReaction = ({
      chatId,
      messageId,
      reactions,
    }: {
      chatId: string;
      messageId: string;
      reactions: Message['reactions'];
    }) => {
      updateMessageInState(chatId, messageId, (message) => ({ ...message, reactions }));
    };

    const handlePinned = ({
      chatId,
      messageId,
      pinnedAt,
      pinnedBy,
    }: {
      chatId: string;
      messageId: string;
      pinnedAt: string | null;
      pinnedBy: string[];
    }) => {
      updateMessageInState(chatId, messageId, (message) => ({
        ...message,
        pinnedAt,
        pinnedBy,
      }));
      void fetchPins(chatId);
      void fetchChats();
    };

    const handleIncomingCall = (payload: IncomingCall) => {
      setIncomingCall(payload);
    };

    const handleAnswered = ({
      callId,
      userId,
      accepted,
    }: {
      callId: string;
      userId: string;
      accepted: boolean;
    }) => {
      const currentCall = callSessionRef.current;
      if (!currentCall || currentCall.callId !== callId) {
        return;
      }

      if (!accepted) {
        endCallLocally();
        return;
      }

      if (currentCall.status === 'outgoing' && currentCall.peerId === userId) {
        void (async () => {
          const peer = ensurePeerConnection(callId, currentCall.peerId);
          const offer = await peer.createOffer();
          await peer.setLocalDescription(offer);

          getSocket()?.emit('webrtc:signal', {
            callId,
            targetUserId: currentCall.peerId,
            signal: {
              type: 'offer',
              offer,
            },
          });
        })();
      }
    };

    const handleWebrtcSignal = ({
      callId,
      fromUserId,
      signal,
    }: {
      callId: string;
      fromUserId: string;
      signal: {
        type: 'offer' | 'answer' | 'candidate';
        offer?: RTCSessionDescriptionInit;
        answer?: RTCSessionDescriptionInit;
        candidate?: RTCIceCandidateInit;
      };
    }) => {
      void (async () => {
        const currentCall = callSessionRef.current;
        if (!currentCall || currentCall.callId !== callId) {
          return;
        }

        const peer = ensurePeerConnection(callId, fromUserId);

        if (signal.type === 'offer' && signal.offer) {
          await peer.setRemoteDescription(new RTCSessionDescription(signal.offer));
          await flushPendingCandidates(peer, callId);
          const answer = await peer.createAnswer();
          await peer.setLocalDescription(answer);

          getSocket()?.emit('webrtc:signal', {
            callId,
            targetUserId: fromUserId,
            signal: {
              type: 'answer',
              answer,
            },
          });

          setCallSession((previous) => (previous ? { ...previous, status: 'active' } : previous));
        }

        if (signal.type === 'answer' && signal.answer) {
          await peer.setRemoteDescription(new RTCSessionDescription(signal.answer));
          await flushPendingCandidates(peer, callId);
          setCallSession((previous) => (previous ? { ...previous, status: 'active' } : previous));
        }

        if (signal.type === 'candidate' && signal.candidate) {
          if (!peer.remoteDescription) {
            pendingCandidatesRef.current[callId] = [
              ...(pendingCandidatesRef.current[callId] ?? []),
              signal.candidate,
            ];
            return;
          }

          await peer.addIceCandidate(new RTCIceCandidate(signal.candidate));
        }
      })();
    };

    const handleCallEnded = ({ callId }: { callId: string }) => {
      const currentCall = callSessionRef.current;
      if (!currentCall || currentCall.callId !== callId) {
        setIncomingCall((previous) => (previous?.callId === callId ? null : previous));
        return;
      }

      endCallLocally();
    };

    socket.on('presence:update', handlePresence);
    socket.on('chat:list:update', handleChatList);
    socket.on('chat:updated', handleChatList);
    socket.on('status:new', handleStatusNew);
    socket.on('message:new', handleMessageNew);
    socket.on('message:updated', handleMessageUpdated);
    socket.on('message:deleted', handleMessageDeleted);
    socket.on('message:seen', handleMessageSeen);
    socket.on('typing:update', handleTyping);
    socket.on('message:reaction', handleReaction);
    socket.on('message:pinned', handlePinned);
    socket.on('call:incoming', handleIncomingCall);
    socket.on('call:answered', handleAnswered);
    socket.on('webrtc:signal', handleWebrtcSignal);
    socket.on('call:ended', handleCallEnded);

    return () => {
      socket.off('presence:update', handlePresence);
      socket.off('chat:list:update', handleChatList);
      socket.off('chat:updated', handleChatList);
      socket.off('status:new', handleStatusNew);
      socket.off('message:new', handleMessageNew);
      socket.off('message:updated', handleMessageUpdated);
      socket.off('message:deleted', handleMessageDeleted);
      socket.off('message:seen', handleMessageSeen);
      socket.off('typing:update', handleTyping);
      socket.off('message:reaction', handleReaction);
      socket.off('message:pinned', handlePinned);
      socket.off('call:incoming', handleIncomingCall);
      socket.off('call:answered', handleAnswered);
      socket.off('webrtc:signal', handleWebrtcSignal);
      socket.off('call:ended', handleCallEnded);
      disconnectSocket();
    };
  }, [
    endCallLocally,
    ensurePeerConnection,
    fetchChats,
    fetchPins,
    flushPendingCandidates,
    markChatAsRead,
    token,
    updateMessageInState,
    user,
  ]);

  useEffect(() => {
    const query = searchTerm.trim();
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }

    const timer = window.setTimeout(async () => {
      try {
        const { data } = await api.get<{ users: User[] }>('/users/search', {
          params: { query },
        });
        setSearchResults(data.users);
      } catch {
        setSearchResults([]);
      }
    }, 250);

    return () => {
      window.clearTimeout(timer);
    };
  }, [searchTerm]);

  function announceTyping() {
    if (!activeChatId) {
      return;
    }

    const socket = getSocket();
    if (!socket) {
      return;
    }

    socket.emit('typing:start', { chatId: activeChatId });

    if (typingTimerRef.current) {
      window.clearTimeout(typingTimerRef.current);
    }

    typingTimerRef.current = window.setTimeout(() => {
      socket.emit('typing:stop', { chatId: activeChatId });
    }, 900);
  }

  function handleFileSelection(event: ChangeEvent<HTMLInputElement>) {
    const files = event.target.files ? [...event.target.files] : [];
    setSelectedFiles((previous) => [...previous, ...files].slice(0, 5));
    event.target.value = '';
  }

  async function handleSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!activeChatId) {
      return;
    }

    if (!composer.trim() && selectedFiles.length === 0) {
      return;
    }

    setErrorText(null);

    try {
      let textPayload = composer;
      let encrypted = false;
      let iv = '';

      if (composer.trim() && encryptOutgoing && activeKey) {
        const encryptedPayload = await encryptText(composer, activeKey, activeChatId);
        textPayload = encryptedPayload.cipherText;
        encrypted = true;
        iv = encryptedPayload.iv;
      }

      const payload = new FormData();
      payload.append('text', textPayload);
      if (replyTo) {
        payload.append('replyTo', replyTo.id);
      }
      if (encrypted) {
        payload.append('encrypted', 'true');
        payload.append('iv', iv);
      }
      selectedFiles.forEach((file) => payload.append('files', file));

      await api.post(`/chats/${activeChatId}/messages`, payload, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setComposer('');
      setSelectedFiles([]);
      setReplyTo(null);
      getSocket()?.emit('typing:stop', { chatId: activeChatId });
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function startDirectChat(targetUserId: string) {
    try {
      const { data } = await api.post<{ chat: Chat }>('/chats/direct', {
        userId: targetUserId,
      });

      await fetchChats();
      setActiveChatId(data.chat.id);
      setMobileView('chat');
      setSearchTerm('');
      setSearchResults([]);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function createGroupChat() {
    if (!groupName.trim() || groupMemberIds.length === 0) {
      setErrorText('Select a group name and at least one member.');
      return;
    }

    try {
      const { data } = await api.post<{ chat: Chat }>('/chats/group', {
        name: groupName,
        description: groupDescription,
        memberIds: groupMemberIds,
      });

      await fetchChats();
      setActiveChatId(data.chat.id);
      setShowGroupModal(false);
      setGroupName('');
      setGroupDescription('');
      setGroupMemberIds([]);
      setMobileView('chat');
      setErrorText(null);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function saveProfile() {
    if (!profileName.trim()) {
      setErrorText('Profile name is required.');
      return;
    }

    setSavingProfile(true);
    setErrorText(null);

    try {
      await updateProfile(profileName, profileAbout);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    } finally {
      setSavingProfile(false);
    }
  }

  async function reactToMessage(messageId: string, emoji: string) {
    try {
      await api.post(`/messages/${messageId}/reactions`, { emoji });
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function pinMessage(message: Message) {
    try {
      await api.post(`/messages/${message.id}/pin`, {
        pinned: !message.pinnedBy.includes(user?.id ?? ''),
      });
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function createStatus() {
    if (!statusText.trim() && !statusFile) {
      setErrorText('Status requires text or media.');
      return;
    }

    try {
      const payload = new FormData();
      payload.append('text', statusText);
      if (statusFile) {
        payload.append('file', statusFile);
      }

      await api.post('/statuses', payload, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setShowStatusComposer(false);
      setStatusText('');
      setStatusFile(null);
      await fetchStatuses();
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function openStatus(status: StatusItem) {
    setViewingStatus(status);

    try {
      await api.post(`/statuses/${status.id}/view`);
    } catch {
      // Best effort.
    }
  }

  function setEncryptionKey() {
    if (!activeChatId) {
      return;
    }

    const current = chatKeys[activeChatId] ?? '';
    const next = window.prompt('Set chat encryption passphrase', current);

    if (next === null) {
      return;
    }

    const trimmed = next.trim();
    if (!trimmed) {
      localStorage.removeItem(keyForChat(activeChatId));
      setChatKeys((previous) => {
        const nextMap = { ...previous };
        delete nextMap[activeChatId];
        return nextMap;
      });
      setEncryptOutgoing(false);
      return;
    }

    localStorage.setItem(keyForChat(activeChatId), trimmed);
    setChatKeys((previous) => ({
      ...previous,
      [activeChatId]: trimmed,
    }));
    setEncryptOutgoing(true);
  }

  async function startCall(type: CallMode) {
    if (!activeChat || !activeChatId || !activeChat.directPeer) {
      setErrorText('Calls are available in direct chats.');
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: type === 'video',
      });

      localStreamRef.current = stream;
      setLocalStream(stream);

      getSocket()?.emit('call:start', { chatId: activeChatId, type }, (response: { ok: boolean; callId?: string; message?: string }) => {
        if (!response.ok || !response.callId) {
          cleanupCallMedia();
          setErrorText(response.message ?? 'Unable to start call.');
          return;
        }

        setCallSession({
          callId: response.callId,
          chatId: activeChatId,
          type,
          peerId: activeChat.directPeer!.id,
          peerName: activeChat.directPeer!.name,
          status: 'outgoing',
        });
      });
    } catch {
      setErrorText('Microphone/camera permission denied.');
    }
  }

  async function acceptIncomingCall() {
    if (!incomingCall) {
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: incomingCall.type === 'video',
      });

      localStreamRef.current = stream;
      setLocalStream(stream);

      getSocket()?.emit('call:answer', {
        callId: incomingCall.callId,
        accepted: true,
      });

      setCallSession({
        callId: incomingCall.callId,
        chatId: incomingCall.chatId,
        type: incomingCall.type,
        peerId: incomingCall.callerId,
        peerName: incomingCall.callerName,
        status: 'incoming',
      });
      setIncomingCall(null);
    } catch {
      setErrorText('Unable to access media devices.');
    }
  }

  function rejectIncomingCall() {
    if (!incomingCall) {
      return;
    }

    getSocket()?.emit('call:answer', {
      callId: incomingCall.callId,
      accepted: false,
    });
    setIncomingCall(null);
  }

  function endCall() {
    if (callSession) {
      getSocket()?.emit('call:end', { callId: callSession.callId });
    }
    endCallLocally();
  }

  async function editMessage(message: Message) {
    const currentText = getDisplayText(message);
    const nextText = window.prompt('Edit message', currentText);
    if (!nextText || !nextText.trim() || nextText.trim() === currentText.trim()) {
      return;
    }

    try {
      if (message.encryption) {
        if (!activeChatId || !activeKey) {
          setErrorText('Set the chat encryption key before editing encrypted messages.');
          return;
        }

        const encryptedPayload = await encryptText(nextText.trim(), activeKey, activeChatId);

        await api.patch(`/messages/${message.id}`, {
          text: encryptedPayload.cipherText,
          encrypted: true,
          iv: encryptedPayload.iv,
        });
        return;
      }

      await api.patch(`/messages/${message.id}`, {
        text: nextText.trim(),
        encrypted: false,
      });
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  async function deleteMessage(message: Message) {
    const confirmed = window.confirm('Delete this message?');
    if (!confirmed) {
      return;
    }

    try {
      await api.delete(`/messages/${message.id}`);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    }
  }

  function messageSeenStatus(message: Message) {
    if (!user || message.senderId !== user.id || !activeChat) {
      return null;
    }

    const seenByOthers = message.seenBy.filter((entry) => entry.userId !== user.id).length;

    if (seenByOthers > 0) {
      return <CheckCheck size={14} className="status-icon status-seen" />;
    }

    return <Check size={14} className="status-icon" />;
  }

  return (
    <main className="chat-layout nova-theme">
      <aside className={clsx('sidebar', mobileView === 'chat' && 'hidden-mobile')}>
        <header className="sidebar-header">
          <div className="profile-inline">
            <Avatar label={user?.name ?? 'Me'} color={user?.avatarColor ?? '#0f9d58'} />
            <div>
              <strong>{user?.name}</strong>
              <span>{user?.email}</span>
            </div>
          </div>

          <div className="header-actions">
            <button className="icon-btn" type="button" onClick={() => setShowStatusComposer(true)}>
              <ImageIcon size={18} />
            </button>
            <button className="icon-btn" type="button" onClick={() => setShowGroupModal(true)}>
              <Users size={19} />
            </button>
          </div>
        </header>

        <div className="search-wrap">
          <Search size={16} />
          <input
            value={chatFilter}
            onChange={(event) => setChatFilter(event.target.value)}
            placeholder="Search chats"
          />
          <button className="icon-btn" type="button" onClick={() => setShowGroupModal(true)}>
            <CirclePlus size={17} />
          </button>
        </div>

        <div className="search-wrap secondary">
          <Search size={16} />
          <input
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Find people by name or email"
          />
        </div>

        {searchResults.length > 0 ? (
          <section className="results-panel">
            {searchResults.map((candidate) => (
              <button
                key={candidate.id}
                className="result-item"
                type="button"
                onClick={() => void startDirectChat(candidate.id)}
              >
                <Avatar label={candidate.name} color={candidate.avatarColor} size={34} />
                <div>
                  <strong>{candidate.name}</strong>
                  <span>{candidate.email}</span>
                </div>
              </button>
            ))}
          </section>
        ) : null}

        <section className="chat-list">
          {loadingChats ? <p className="muted">Loading chats...</p> : null}
          {!loadingChats && filteredChats.length === 0 ? (
            <p className="muted">No chats yet. Start with email search above.</p>
          ) : null}

          {filteredChats.map((chat) => {
            const active = chat.id === activeChatId;
            const peerOnline =
              chat.type === 'direct' && chat.directPeer ? onlineUserIds.has(chat.directPeer.id) : false;

            return (
              <button
                type="button"
                key={chat.id}
                className={clsx('chat-item', active && 'active')}
                onClick={() => {
                  setActiveChatId(chat.id);
                  setMobileView('chat');
                }}
              >
                <div className="chat-item-avatar">
                  <Avatar label={chat.title} color={chat.avatarColor} size={45} />
                  {peerOnline ? <span className="online-dot" /> : null}
                </div>
                <div className="chat-item-body">
                  <div className="chat-item-top">
                    <strong>{chat.title}</strong>
                    <span>{formatChatTime(chat.lastMessage?.createdAt ?? chat.lastMessageAt)}</span>
                  </div>
                  <div className="chat-item-bottom">
                    <span>{summarizeMessage(chat.lastMessage)}</span>
                    <div className="mini-badges">
                      {chat.pinnedCount > 0 ? <small>{chat.pinnedCount} pin</small> : null}
                      {chat.unreadCount > 0 ? <em>{chat.unreadCount}</em> : null}
                    </div>
                  </div>
                </div>
              </button>
            );
          })}
        </section>

        <section className="status-strip">
          <button className="status-create" type="button" onClick={() => setShowStatusComposer(true)}>
            <CirclePlus size={16} />
            Add status
          </button>
          <div className="status-list">
            {statusCards.length === 0 ? <span className="muted-inline">No status updates</span> : null}
            {statusCards.map((status) => (
              <button
                key={status.id}
                className={clsx('status-chip', status.seen && 'seen')}
                type="button"
                onClick={() => void openStatus(status)}
              >
                <Avatar
                  label={status.user?.name ?? 'User'}
                  color={status.user?.avatarColor ?? '#3557e0'}
                  size={30}
                />
                <span>{status.user?.name ?? 'Unknown'}</span>
              </button>
            ))}
          </div>
        </section>

        <section className="profile-panel compact">
          <label>
            <span>Name</span>
            <input
              value={profileName}
              onChange={(event) => setProfileName(event.target.value)}
              maxLength={30}
            />
          </label>
          <label>
            <span>About</span>
            <input
              value={profileAbout}
              onChange={(event) => setProfileAbout(event.target.value)}
              maxLength={120}
            />
          </label>
          <div className="profile-actions">
            <button className="primary-btn" type="button" onClick={saveProfile} disabled={savingProfile}>
              {savingProfile ? 'Saving...' : 'Save'}
            </button>
            <button className="ghost-btn" type="button" onClick={logout}>
              <LogOut size={15} />
              Logout
            </button>
          </div>
        </section>
      </aside>

      <section className={clsx('chat-main', mobileView === 'list' && 'hidden-mobile')}>
        {activeChat ? (
          <>
            <header className="chat-main-header">
              <div className="chat-main-header-info">
                <button className="icon-btn mobile-only" type="button" onClick={() => setMobileView('list')}>
                  <ArrowLeft size={18} />
                </button>
                <Avatar label={activeChat.title} color={activeChat.avatarColor} size={43} />
                <div>
                  <strong>{activeChat.title}</strong>
                  <span>
                    {typingLabel ||
                      (activeChat.type === 'direct'
                        ? isPeerOnline
                          ? 'online'
                          : activeChat.directPeer?.lastSeen
                            ? `last seen ${formatChatTime(activeChat.directPeer.lastSeen)}`
                            : 'offline'
                        : `${activeChat.members.length} members`)}
                  </span>
                </div>
              </div>

              <div className="chat-header-actions">
                <button className="icon-btn" type="button" onClick={setEncryptionKey} title="Set encryption key">
                  <KeyRound size={16} />
                </button>
                {activeChat.type === 'direct' ? (
                  <>
                    <button className="icon-btn" type="button" onClick={() => void startCall('audio')}>
                      <Phone size={16} />
                    </button>
                    <button className="icon-btn" type="button" onClick={() => void startCall('video')}>
                      <Video size={16} />
                    </button>
                  </>
                ) : null}
              </div>
            </header>

            {activePins.length > 0 ? (
              <div className="pin-banner">
                <button className="pin-toggle" type="button" onClick={() => setShowPinned((previous) => !previous)}>
                  <Pin size={15} />
                  {activePins.length} pinned
                </button>
                {showPinned ? (
                  <ul>
                    {activePins.slice(0, 3).map((pinned) => (
                      <li key={pinned.id}>{getDisplayText(pinned).slice(0, 72)}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : null}

            <div className="security-row">
              <Shield size={14} />
              <span>{activeKey ? 'End-to-end encryption key is set for this chat.' : 'Encryption key not set.'}</span>
              <label className="switch-inline">
                <input
                  type="checkbox"
                  checked={encryptOutgoing && Boolean(activeKey)}
                  onChange={(event) => setEncryptOutgoing(event.target.checked)}
                  disabled={!activeKey}
                />
                Encrypt outgoing text
              </label>
            </div>

            <div className="message-list" ref={listRef}>
              {loadingMessages ? <p className="muted">Loading messages...</p> : null}
              {activeMessages.map((message) => {
                const mine = message.senderId === user?.id;
                const decryptedText = getDisplayText(message);

                return (
                  <article key={message.id} className={clsx('message-row', mine ? 'mine' : 'theirs')}>
                    <div className={clsx('bubble', message.isDeleted && 'deleted')}>
                      {!mine ? <strong className="sender-name">{message.sender?.name ?? 'Unknown'}</strong> : null}

                      {message.replyToMessage ? (
                        <div className="reply-snippet">
                          <span>{message.replyToMessage.senderName}</span>
                          <p>{message.replyToMessage.text}</p>
                        </div>
                      ) : null}

                      {message.isDeleted ? <p className="deleted-text">This message was deleted.</p> : null}

                      {!message.isDeleted ? (
                        <p className={clsx(message.encryption && 'encrypted-text')}>{decryptedText}</p>
                      ) : null}

                      {!message.isDeleted && message.attachments.length > 0 ? (
                        <div className="attachments">
                          {message.attachments.map((attachment) => {
                            const imageAttachment = attachment.mimeType.startsWith('image/');
                            if (imageAttachment) {
                              return (
                                <a
                                  key={attachment.id}
                                  href={attachment.url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="img-attachment"
                                >
                                  <img src={attachment.url} alt={attachment.name} />
                                </a>
                              );
                            }

                            return (
                              <a
                                key={attachment.id}
                                href={attachment.url}
                                target="_blank"
                                rel="noreferrer"
                                className="file-attachment"
                              >
                                <Paperclip size={14} />
                                {attachment.name}
                              </a>
                            );
                          })}
                        </div>
                      ) : null}

                      {message.reactions.length > 0 ? (
                        <div className="reaction-strip">
                          {message.reactions.map((reaction) => (
                            <button
                              key={reaction.emoji}
                              type="button"
                              onClick={() => void reactToMessage(message.id, reaction.emoji)}
                              className={clsx(
                                'reaction-pill',
                                reaction.userIds.includes(user?.id ?? '') && 'active',
                              )}
                            >
                              {reaction.emoji} {reaction.userIds.length}
                            </button>
                          ))}
                        </div>
                      ) : null}

                      <footer>
                        <time>{formatMessageTime(message.createdAt)}</time>
                        {message.editedAt ? <span className="edited">edited</span> : null}
                        {message.encryption ? <Shield size={12} /> : null}
                        {message.pinnedAt ? <Pin size={12} /> : null}
                        {messageSeenStatus(message)}
                      </footer>

                      {!message.isDeleted && (
                        <div className="message-actions expanded">
                          <button type="button" onClick={() => setReplyTo(message)}>
                            Reply
                          </button>
                          <button type="button" onClick={() => void pinMessage(message)}>
                            <Pin size={13} />
                          </button>
                          {mine ? (
                            <>
                              <button type="button" onClick={() => void editMessage(message)}>
                                <Edit3 size={13} />
                              </button>
                              <button type="button" onClick={() => void deleteMessage(message)}>
                                <Trash2 size={13} />
                              </button>
                            </>
                          ) : null}
                          <div className="quick-reactions">
                            <Smile size={13} />
                            {REACTION_CHOICES.map((emoji) => (
                              <button key={emoji} type="button" onClick={() => void reactToMessage(message.id, emoji)}>
                                {emoji}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>

            <form className="composer" onSubmit={handleSendMessage}>
              {replyTo ? (
                <div className="reply-strip">
                  <div>
                    <strong>Replying to {replyTo.sender?.name ?? 'Unknown'}</strong>
                    <p>{getDisplayText(replyTo) || 'Attachment'}</p>
                  </div>
                  <button type="button" onClick={() => setReplyTo(null)}>
                    <X size={15} />
                  </button>
                </div>
              ) : null}

              {selectedFiles.length > 0 ? (
                <div className="file-strip">
                  {selectedFiles.map((file, index) => (
                    <span key={`${file.name}-${index}`}>
                      {file.name}
                      <button
                        type="button"
                        onClick={() =>
                          setSelectedFiles((previous) => previous.filter((_, fileIndex) => fileIndex !== index))
                        }
                      >
                        <X size={12} />
                      </button>
                    </span>
                  ))}
                </div>
              ) : null}

              <div className="composer-row">
                <label className="icon-btn attach-btn">
                  <input type="file" hidden multiple onChange={handleFileSelection} />
                  <Paperclip size={18} />
                </label>
                <label className="icon-btn attach-btn">
                  <input type="file" hidden accept="image/*" multiple onChange={handleFileSelection} />
                  <ImageIcon size={18} />
                </label>
                <input
                  value={composer}
                  onChange={(event) => {
                    setComposer(event.target.value);
                    announceTyping();
                  }}
                  placeholder="Type a message"
                />
                <button className="send-btn" type="submit">
                  {encryptOutgoing && activeKey ? <Shield size={15} /> : <SendHorizontal size={17} />}
                </button>
              </div>
            </form>
          </>
        ) : (
          <div className="empty-state">
            <h2>Your chats will appear here</h2>
            <p>Use search to find contacts by email and start messaging instantly.</p>
          </div>
        )}
      </section>

      {showGroupModal ? (
        <section className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card">
            <header>
              <h3>Create group</h3>
              <button className="icon-btn" type="button" onClick={() => setShowGroupModal(false)}>
                <X size={16} />
              </button>
            </header>

            <label>
              <span>Group name</span>
              <input
                value={groupName}
                onChange={(event) => setGroupName(event.target.value)}
                placeholder="Project Team"
              />
            </label>

            <label>
              <span>Description</span>
              <input
                value={groupDescription}
                onChange={(event) => setGroupDescription(event.target.value)}
                placeholder="Optional"
              />
            </label>

            <div className="member-picker">
              {directoryUsers.map((candidate) => (
                <button
                  key={candidate.id}
                  type="button"
                  className={clsx('member-item', groupMemberIds.includes(candidate.id) && 'selected')}
                  onClick={() =>
                    setGroupMemberIds((previous) =>
                      previous.includes(candidate.id)
                        ? previous.filter((id) => id !== candidate.id)
                        : [...previous, candidate.id],
                    )
                  }
                >
                  <Avatar label={candidate.name} color={candidate.avatarColor} size={34} />
                  <div>
                    <strong>{candidate.name}</strong>
                    <span>{candidate.email}</span>
                  </div>
                </button>
              ))}
            </div>

            <button className="primary-btn" type="button" onClick={() => void createGroupChat()}>
              Create group
            </button>
          </div>
        </section>
      ) : null}

      {showStatusComposer ? (
        <section className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card">
            <header>
              <h3>Create status</h3>
              <button className="icon-btn" type="button" onClick={() => setShowStatusComposer(false)}>
                <X size={16} />
              </button>
            </header>

            <label>
              <span>Text</span>
              <input
                value={statusText}
                onChange={(event) => setStatusText(event.target.value)}
                maxLength={220}
                placeholder="What is new today?"
              />
            </label>

            <label>
              <span>Image/Video</span>
              <input
                type="file"
                accept="image/*,video/*"
                onChange={(event) => setStatusFile(event.target.files?.[0] ?? null)}
              />
            </label>

            <button className="primary-btn" type="button" onClick={() => void createStatus()}>
              Post status
            </button>
          </div>
        </section>
      ) : null}

      {viewingStatus ? (
        <section className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card status-viewer">
            <header>
              <h3>{viewingStatus.user?.name ?? 'Status'}</h3>
              <button className="icon-btn" type="button" onClick={() => setViewingStatus(null)}>
                <X size={16} />
              </button>
            </header>

            <p>{viewingStatus.text}</p>
            {viewingStatus.attachment ? (
              <div className="status-media">
                {viewingStatus.attachment.mimeType.startsWith('video/') ? (
                  <video controls src={viewingStatus.attachment.url} />
                ) : (
                  <img src={viewingStatus.attachment.url} alt={viewingStatus.attachment.name} />
                )}
              </div>
            ) : null}
            <small>{formatChatTime(viewingStatus.createdAt)}</small>
          </div>
        </section>
      ) : null}

      {incomingCall ? (
        <section className="call-toast">
          <div>
            <strong>{incomingCall.callerName}</strong>
            <p>
              Incoming {incomingCall.type} call <Phone size={13} />
            </p>
          </div>
          <div className="call-toast-actions">
            <button className="ghost-btn" type="button" onClick={rejectIncomingCall}>
              Decline
            </button>
            <button className="primary-btn" type="button" onClick={() => void acceptIncomingCall()}>
              Accept
            </button>
          </div>
        </section>
      ) : null}

      {callSession ? (
        <section className="call-overlay">
          <div className="call-card">
            <header>
              <strong>{callSession.peerName}</strong>
              <span>
                {callSession.status === 'outgoing'
                  ? 'Ringing...'
                  : callSession.status === 'incoming'
                    ? 'Connecting...'
                    : 'In call'}
              </span>
            </header>

            <div className="call-media">
              {callSession.type === 'video' ? (
                <>
                  <video ref={remoteVideoRef} autoPlay playsInline className="remote-video" />
                  <video ref={localVideoRef} autoPlay muted playsInline className="local-video" />
                </>
              ) : (
                <div className="audio-call-badge">
                  <audio ref={remoteAudioRef} autoPlay playsInline />
                  <Mic size={32} />
                  <p>Audio call active</p>
                </div>
              )}
            </div>

            <button className="danger-btn" type="button" onClick={endCall}>
              End call
            </button>
          </div>
        </section>
      ) : null}

      {errorText ? <p className="floating-error">{errorText}</p> : null}
    </main>
  );
}
