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
  Bell,
  Camera,
  Check,
  CheckCheck,
  ChevronDown,
  CirclePlus,
  Edit3,
  Image as ImageIcon,
  KeyRound,
  LogOut,
  MessageCircle,
  Mic,
  MicOff,
  Moon,
  Paperclip,
  Phone,
  Pin,
  Search,
  SendHorizontal,
  Shield,
  Smile,
  Trash2,
  Video,
  VideoOff,
  Sun,
  Volume2,
  VolumeX,
  X,
} from 'lucide-react';

import { useAuth } from '../context/useAuth';
import { decryptText, encryptText } from '../lib/crypto';
import { api } from '../lib/api';
import { connectSocket, disconnectSocket, getSocket } from '../lib/socket';
import type { Chat, Message, User } from '../types';

const REACTION_CHOICES = ['??', '??', '??', '??', '??', '??'];
const ENCRYPTED_PLACEHOLDER = '__encrypted__';
const ENCRYPTION_FAIL = '__decrypt_fail__';

type CallMode = 'audio' | 'video';
type ChatListTab = 'all' | 'unread' | 'favorites' | 'groups';
type ThemeMode = 'light' | 'dark';
type AlertType = 'message' | 'call';

type ChatScreenProps = {
  theme: ThemeMode;
  onToggleTheme: () => void;
};

type AlertItem = {
  id: string;
  type: AlertType;
  chatId: string;
  title: string;
  detail: string;
  createdAt: string;
  read: boolean;
};

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

function Avatar({
  label,
  color,
  imageUrl,
  size = 42,
}: {
  label: string;
  color: string;
  imageUrl?: string | null;
  size?: number;
}) {
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
      {imageUrl ? <img src={imageUrl} alt={label} /> : getInitials(label)}
    </span>
  );
}

function sortChats(items: Chat[]) {
  return [...items].sort(
    (a, b) => +new Date(b.lastMessageAt ?? b.updatedAt) - +new Date(a.lastMessageAt ?? a.updatedAt),
  );
}

function keyForChat(chatId: string) {
  return `chatrix-e2ee:${chatId}`;
}

export function ChatScreen({ theme, onToggleTheme }: ChatScreenProps) {
  const { user, token, logout, updateProfile, uploadAvatar, removeAvatar } = useAuth();

  const [chats, setChats] = useState<Chat[]>([]);
  const [messagesByChat, setMessagesByChat] = useState<Record<string, Message[]>>({});
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [chatFilter, setChatFilter] = useState('');
  const [chatListTab, setChatListTab] = useState<ChatListTab>('all');
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

  const [chatKeys, setChatKeys] = useState<Record<string, string>>({});
  const [decryptedMap, setDecryptedMap] = useState<Record<string, string>>({});

  const [pinsByChat, setPinsByChat] = useState<Record<string, Message[]>>({});
  const [showPinned, setShowPinned] = useState(true);

  const [incomingCall, setIncomingCall] = useState<IncomingCall | null>(null);
  const [callSession, setCallSession] = useState<CallSession | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [micMuted, setMicMuted] = useState(false);
  const [cameraOff, setCameraOff] = useState(false);
  const [speakerMuted, setSpeakerMuted] = useState(false);

  const [errorText, setErrorText] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [showAlerts, setShowAlerts] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [profileName, setProfileName] = useState(user?.name ?? '');
  const [profileAbout, setProfileAbout] = useState(user?.about ?? '');
  const [savingProfile, setSavingProfile] = useState(false);
  const [uploadingAvatar, setUploadingAvatar] = useState(false);

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
  const topbarMenusRef = useRef<HTMLDivElement | null>(null);
  const avatarInputRef = useRef<HTMLInputElement | null>(null);

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
    return chats.filter((chat) => {
      const matchesQuery =
        !query ||
        chat.title.toLowerCase().includes(query) ||
        summarizeMessage(chat.lastMessage).toLowerCase().includes(query);

      if (!matchesQuery) {
        return false;
      }

      if (chatListTab === 'unread') {
        return chat.unreadCount > 0;
      }

      if (chatListTab === 'favorites') {
        return chat.pinnedCount > 0;
      }

      if (chatListTab === 'groups') {
        return chat.type === 'group';
      }

      return true;
    });
  }, [chatFilter, chatListTab, chats]);

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

  const isPeerOnline = useMemo(() => {
    if (!activeChat || !activeChat.directPeer) {
      return false;
    }

    return onlineUserIds.has(activeChat.directPeer.id);
  }, [activeChat, onlineUserIds]);

  const unreadAlertsCount = useMemo(
    () => alerts.reduce((count, entry) => (entry.read ? count : count + 1), 0),
    [alerts],
  );

  const addAlert = useCallback(
    (payload: { type: AlertType; chatId: string; title: string; detail: string; notifyBrowser?: boolean }) => {
      const entry: AlertItem = {
        id: crypto.randomUUID(),
        type: payload.type,
        chatId: payload.chatId,
        title: payload.title,
        detail: payload.detail,
        createdAt: new Date().toISOString(),
        read: false,
      };

      setAlerts((previous) => [entry, ...previous].slice(0, 40));

      if (
        payload.notifyBrowser &&
        typeof window !== 'undefined' &&
        'Notification' in window &&
        Notification.permission === 'granted'
      ) {
        const browserNote = new Notification(payload.title, { body: payload.detail });
        browserNote.onclick = () => {
          window.focus();
          setActiveChatId(payload.chatId);
          setMobileView('chat');
        };
      }
    },
    [],
  );

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
    setMicMuted(false);
    setCameraOff(false);
    setSpeakerMuted(false);
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
        const incomingTracks =
          event.streams.length > 0
            ? event.streams.flatMap((streamFromEvent) => streamFromEvent.getTracks())
            : [event.track];

        // Some browsers emit audio/video tracks separately; merge by track id.
        setRemoteStream((previous) => {
          const byTrackId = new Map<string, MediaStreamTrack>();
          for (const track of previous?.getTracks() ?? []) {
            byTrackId.set(track.id, track);
          }
          for (const track of incomingTracks) {
            byTrackId.set(track.id, track);
          }
          return new MediaStream([...byTrackId.values()]);
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

      peer.onconnectionstatechange = () => {
        if (peer.connectionState === 'connected') {
          setCallSession((previous) => (previous ? { ...previous, status: 'active' } : previous));
          return;
        }

        if (peer.connectionState === 'failed' || peer.connectionState === 'disconnected') {
          const activeCall = callSessionRef.current;
          if (!activeCall || activeCall.callId !== callId) {
            return;
          }
          endCallLocally();
          setErrorText('Call connection lost.');
        }
      };

      peerRef.current = peer;
      return peer;
    },
    [endCallLocally],
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
    let mounted = true;

    async function bootstrap() {
      setLoadingChats(true);
      setErrorText(null);

      try {
        await Promise.all([fetchChats(), fetchDirectory()]);
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
  }, [fetchChats, fetchDirectory]);

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
    if (!localStream) {
      return;
    }

    localStream.getAudioTracks().forEach((track) => {
      track.enabled = !micMuted;
    });
    localStream.getVideoTracks().forEach((track) => {
      track.enabled = !cameraOff;
    });
  }, [cameraOff, localStream, micMuted]);

  useEffect(() => {
    if (remoteVideoRef.current) {
      if (!remoteStream || callSession?.type !== 'video') {
        remoteVideoRef.current.srcObject = null;
      } else {
        const remoteVideoTracks = remoteStream.getVideoTracks();
        remoteVideoRef.current.srcObject =
          remoteVideoTracks.length > 0 ? new MediaStream(remoteVideoTracks) : null;
        remoteVideoRef.current.muted = true;
        remoteVideoRef.current.volume = 1;
        void remoteVideoRef.current.play().catch(() => {
          // Autoplay can fail silently on some browsers until user gesture.
        });
      }
    }

    if (remoteAudioRef.current) {
      if (!remoteStream) {
        remoteAudioRef.current.srcObject = null;
      } else {
        const remoteAudioTracks = remoteStream.getAudioTracks();
        remoteAudioRef.current.srcObject =
          remoteAudioTracks.length > 0 ? new MediaStream(remoteAudioTracks) : null;
        remoteAudioRef.current.muted = speakerMuted;
        remoteAudioRef.current.volume = 1;
        void remoteAudioRef.current.play().catch(() => {
          // Autoplay can fail silently on some browsers until user gesture.
        });
      }
    }
  }, [callSession, remoteStream, speakerMuted]);

  useEffect(() => {
    callSessionRef.current = callSession;
  }, [callSession]);

  useEffect(() => {
    activeChatIdRef.current = activeChatId;
  }, [activeChatId]);

  useEffect(() => {
    if (!user) {
      return;
    }
    setProfileName(user.name);
    setProfileAbout(user.about ?? '');
  }, [user]);

  useEffect(() => {
    const onPointerDown = (event: PointerEvent) => {
      if (!topbarMenusRef.current) {
        return;
      }
      if (!topbarMenusRef.current.contains(event.target as Node)) {
        setShowAlerts(false);
        setShowProfileMenu(false);
      }
    };

    window.addEventListener('pointerdown', onPointerDown);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
    };
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      return;
    }

    if (Notification.permission === 'default') {
      void Notification.requestPermission().catch(() => {
        // Ignore blocked notification prompts.
      });
    }
  }, []);

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

    const handleMessageNew = ({ chatId, message }: { chatId: string; message: Message }) => {
      const incomingFromPeer = message.senderId !== user.id;

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

      if (incomingFromPeer) {
        addAlert({
          type: 'message',
          chatId,
          title: message.sender?.name ? `New message from ${message.sender.name}` : 'New message',
          detail: summarizeMessage(message),
          notifyBrowser: document.hidden,
        });
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
      addAlert({
        type: 'call',
        chatId: payload.chatId,
        title: `Incoming ${payload.type} call`,
        detail: `${payload.callerName} is calling you.`,
        notifyBrowser: document.hidden,
      });
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

    const handleCallEnded = ({
      callId,
      reason,
      endedBy,
    }: {
      callId: string;
      reason?: string;
      endedBy?: string;
    }) => {
      const currentCall = callSessionRef.current;
      if (!currentCall || currentCall.callId !== callId) {
        setIncomingCall((previous) => (previous?.callId === callId ? null : previous));
        return;
      }

      if (reason && endedBy && endedBy !== user.id) {
        addAlert({
          type: 'call',
          chatId: currentCall.chatId,
          title: 'Call ended',
          detail: `${currentCall.peerName} ${reason === 'rejected' ? 'declined the call.' : 'left the call.'}`,
          notifyBrowser: false,
        });
      }

      endCallLocally();
    };

    socket.on('presence:update', handlePresence);
    socket.on('chat:list:update', handleChatList);
    socket.on('chat:updated', handleChatList);
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
    addAlert,
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

  function toggleAlertsPanel() {
    setShowProfileMenu(false);
    setShowAlerts((previous) => {
      const next = !previous;
      if (next) {
        setAlerts((current) => current.map((entry) => ({ ...entry, read: true })));
      }
      return next;
    });
  }

  function openAlert(alert: AlertItem) {
    setActiveChatId(alert.chatId);
    setMobileView('chat');
    setShowAlerts(false);
    setAlerts((previous) =>
      previous.map((entry) => (entry.id === alert.id ? { ...entry, read: true } : entry)),
    );
  }

  async function saveProfile() {
    if (!profileName.trim()) {
      setErrorText('Profile name is required.');
      return;
    }

    setSavingProfile(true);
    setErrorText(null);

    try {
      await updateProfile(profileName.trim(), profileAbout.trim());
      await Promise.all([fetchChats(), fetchDirectory()]);
      setShowProfileModal(false);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    } finally {
      setSavingProfile(false);
    }
  }

  async function handleAvatarChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }

    if (!file.type.startsWith('image/')) {
      setErrorText('Please select an image file for profile photo.');
      return;
    }

    setUploadingAvatar(true);
    setErrorText(null);
    try {
      await uploadAvatar(file);
      await Promise.all([fetchChats(), fetchDirectory()]);
      setShowProfileMenu(false);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    } finally {
      setUploadingAvatar(false);
    }
  }

  async function handleAvatarRemove() {
    if (!user?.avatarUrl) {
      return;
    }

    setUploadingAvatar(true);
    setErrorText(null);
    try {
      await removeAvatar();
      await Promise.all([fetchChats(), fetchDirectory()]);
      setShowProfileMenu(false);
    } catch (error) {
      setErrorText(apiErrorMessage(error));
    } finally {
      setUploadingAvatar(false);
    }
  }

  async function requestCallMedia(type: CallMode): Promise<{ stream: MediaStream; hasVideo: boolean }> {
    const audioConstraints: MediaTrackConstraints = {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    };

    if (type === 'audio') {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: audioConstraints,
        video: false,
      });
      return { stream, hasVideo: false };
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: audioConstraints,
        video: {
          facingMode: 'user',
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
      });
      return { stream, hasVideo: stream.getVideoTracks().length > 0 };
    } catch {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: audioConstraints,
          video: {
            facingMode: 'user',
          },
        });
        return { stream, hasVideo: stream.getVideoTracks().length > 0 };
      } catch {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: audioConstraints,
          video: false,
        });
        return { stream, hasVideo: false };
      }
    }
  }

  async function startCall(type: CallMode) {
    if (!activeChat || !activeChatId || !activeChat.directPeer) {
      setErrorText('Calls are available in direct chats.');
      return;
    }

    try {
      setErrorText(null);
      setMicMuted(false);
      setCameraOff(false);
      setSpeakerMuted(false);

      const { stream, hasVideo } = await requestCallMedia(type);
      if (type === 'video' && !hasVideo) {
        setCameraOff(true);
        setErrorText('Camera unavailable. Starting call with audio only.');
      }

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
      setErrorText(null);
      setMicMuted(false);
      setCameraOff(false);
      setSpeakerMuted(false);

      const { stream, hasVideo } = await requestCallMedia(incomingCall.type);
      if (incomingCall.type === 'video' && !hasVideo) {
        setCameraOff(true);
        setErrorText('Camera unavailable. Joined call with audio only.');
      }

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

  function toggleMute() {
    setMicMuted((previous) => !previous);
  }

  function toggleCamera() {
    if (callSession?.type !== 'video') {
      return;
    }
    setCameraOff((previous) => !previous);
  }

  function toggleSpeaker() {
    setSpeakerMuted((previous) => !previous);
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
    <main className="chat-shell">
      <header className="workspace-topbar">
        <div className="workspace-brand">
          <strong>chatrix</strong>
        </div>

        <div className="workspace-search">
          <Search size={16} />
          <input
            value={chatFilter}
            onChange={(event) => setChatFilter(event.target.value)}
            placeholder="Search..."
          />
        </div>

        <div className="workspace-actions" ref={topbarMenusRef}>
          <button
            className="icon-btn topbar-icon"
            type="button"
            aria-label="Alerts"
            onClick={toggleAlertsPanel}
          >
            <Bell size={16} />
            {unreadAlertsCount > 0 ? <span className="alert-dot">{Math.min(unreadAlertsCount, 9)}</span> : null}
          </button>
          <button
            className="icon-btn topbar-icon"
            type="button"
            onClick={onToggleTheme}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
          >
            {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
          </button>
          <button
            className="icon-btn topbar-icon"
            type="button"
            aria-label="New conversation"
            onClick={() => setShowGroupModal(true)}
          >
            <MessageCircle size={16} />
          </button>

          <button
            className="profile-trigger"
            type="button"
            aria-label="Profile menu"
            onClick={() => {
              setShowAlerts(false);
              setShowProfileMenu((previous) => !previous);
            }}
          >
            <Avatar
              label={user?.name ?? 'Me'}
              color={user?.avatarColor ?? '#0f9d58'}
              imageUrl={user?.avatarUrl}
              size={34}
            />
            <ChevronDown size={14} />
          </button>
          <input
            ref={avatarInputRef}
            type="file"
            hidden
            accept="image/*"
            onChange={(event) => void handleAvatarChange(event)}
          />

          {showAlerts ? (
            <section className="alerts-panel">
              <header>
                <strong>Alerts</strong>
                <button
                  type="button"
                  className="ghost-btn"
                  onClick={() => setAlerts([])}
                  disabled={alerts.length === 0}
                >
                  Clear
                </button>
              </header>
              {alerts.length === 0 ? <p className="muted">No alerts yet.</p> : null}
              {alerts.map((alert) => (
                <button
                  key={alert.id}
                  type="button"
                  className={clsx('alert-item', !alert.read && 'unread')}
                  onClick={() => openAlert(alert)}
                >
                  <div>
                    <strong>{alert.title}</strong>
                    <span>{alert.detail}</span>
                  </div>
                  <time>{formatChatTime(alert.createdAt)}</time>
                </button>
              ))}
            </section>
          ) : null}

          {showProfileMenu ? (
            <section className="profile-menu">
              <button
                type="button"
                onClick={() => {
                  setShowProfileModal(true);
                  setShowProfileMenu(false);
                }}
              >
                Edit profile
              </button>
              <button
                type="button"
                onClick={() => avatarInputRef.current?.click()}
                disabled={uploadingAvatar}
              >
                {uploadingAvatar ? 'Uploading...' : 'Upload photo'}
              </button>
              <button
                type="button"
                onClick={() => void handleAvatarRemove()}
                disabled={!user?.avatarUrl || uploadingAvatar}
              >
                Remove photo
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowProfileMenu(false);
                  logout();
                }}
              >
                <LogOut size={14} />
                Logout
              </button>
            </section>
          ) : null}
        </div>
      </header>

      <section className="chat-layout">
        <aside className={clsx('sidebar', mobileView === 'chat' && 'hidden-mobile')}>
          <header className="sidebar-header sidebar-heading">
            <h2>Messages</h2>
            <button className="icon-btn" type="button" onClick={() => setShowGroupModal(true)}>
              <CirclePlus size={16} />
            </button>
          </header>

          <div className="sidebar-tabs">
            <button className={clsx(chatListTab === 'all' && 'active')} type="button" onClick={() => setChatListTab('all')}>
              All messages
            </button>
            <button className={clsx(chatListTab === 'unread' && 'active')} type="button" onClick={() => setChatListTab('unread')}>
              Unread
            </button>
            <button
              className={clsx(chatListTab === 'favorites' && 'active')}
              type="button"
              onClick={() => setChatListTab('favorites')}
            >
              Favorites
            </button>
            <button className={clsx(chatListTab === 'groups' && 'active')} type="button" onClick={() => setChatListTab('groups')}>
              Groups
            </button>
          </div>

          <div className="search-wrap secondary sidebar-search">
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
                  <Avatar
                    label={candidate.name}
                    color={candidate.avatarColor}
                    imageUrl={candidate.avatarUrl}
                    size={34}
                  />
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
              <p className="muted">
                {chatListTab === 'unread'
                  ? 'No unread chats.'
                  : chatListTab === 'favorites'
                    ? 'No favorite chats yet.'
                    : chatListTab === 'groups'
                      ? 'No group chats yet.'
                      : 'No chats yet. Start with email search above.'}
              </p>
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
                    <Avatar label={chat.title} color={chat.avatarColor} imageUrl={chat.avatarUrl} size={45} />
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
        </aside>

        <section className={clsx('chat-main', mobileView === 'list' && 'hidden-mobile')}>
          {activeChat ? (
            <>
            <header className="chat-main-header">
              <div className="chat-main-header-info">
                <button className="icon-btn mobile-only" type="button" onClick={() => setMobileView('list')}>
                  <ArrowLeft size={18} />
                </button>
                <Avatar
                  label={activeChat.title}
                  color={activeChat.avatarColor}
                  imageUrl={activeChat.avatarUrl}
                  size={43}
                />
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
              <span className="empty-icon">💬</span>
              <h2>No conversation selected</h2>
              <p>You can view your conversation in the side bar</p>
            </div>
          )}
        </section>
      </section>

      {showProfileModal ? (
        <section className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card profile-modal">
            <header>
              <h3>Profile</h3>
              <button className="icon-btn" type="button" onClick={() => setShowProfileModal(false)}>
                <X size={16} />
              </button>
            </header>

            <div className="profile-modal-avatar">
              <Avatar
                label={user?.name ?? 'Me'}
                color={user?.avatarColor ?? '#0f9d58'}
                imageUrl={user?.avatarUrl}
                size={74}
              />
              <button
                className="ghost-btn"
                type="button"
                onClick={() => avatarInputRef.current?.click()}
                disabled={uploadingAvatar}
              >
                <Camera size={14} />
                {uploadingAvatar ? 'Uploading...' : 'Change photo'}
              </button>
            </div>

            <label>
              <span>Name</span>
              <input value={profileName} onChange={(event) => setProfileName(event.target.value)} maxLength={30} />
            </label>

            <label>
              <span>About</span>
              <input
                value={profileAbout}
                onChange={(event) => setProfileAbout(event.target.value)}
                maxLength={120}
              />
            </label>

            <button className="primary-btn" type="button" onClick={() => void saveProfile()} disabled={savingProfile}>
              {savingProfile ? 'Saving...' : 'Save profile'}
            </button>
          </div>
        </section>
      ) : null}

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
                  <Avatar
                    label={candidate.name}
                    color={candidate.avatarColor}
                    imageUrl={candidate.avatarUrl}
                    size={34}
                  />
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
              <audio ref={remoteAudioRef} autoPlay playsInline className="remote-audio" />
              {callSession.type === 'video' ? (
                <>
                  <video ref={remoteVideoRef} autoPlay playsInline className="remote-video" />
                  <video ref={localVideoRef} autoPlay muted playsInline className="local-video" />
                  {cameraOff || (localStream?.getVideoTracks().length ?? 0) === 0 ? (
                    <div className="local-video-placeholder">
                      <VideoOff size={16} />
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="audio-call-badge">
                  <Mic size={32} />
                  <p>Audio call active</p>
                </div>
              )}
            </div>

            <div className="call-controls">
              <button
                className={clsx('icon-btn', micMuted && 'active-control')}
                type="button"
                onClick={toggleMute}
                title={micMuted ? 'Unmute microphone' : 'Mute microphone'}
              >
                {micMuted ? <MicOff size={16} /> : <Mic size={16} />}
              </button>
              {callSession.type === 'video' ? (
                <button
                  className={clsx('icon-btn', cameraOff && 'active-control')}
                  type="button"
                  onClick={toggleCamera}
                  title={cameraOff ? 'Turn on camera' : 'Turn off camera'}
                >
                  {cameraOff ? <VideoOff size={16} /> : <Video size={16} />}
                </button>
              ) : null}
              <button
                className={clsx('icon-btn', speakerMuted && 'active-control')}
                type="button"
                onClick={toggleSpeaker}
                title={speakerMuted ? 'Unmute speaker' : 'Mute speaker'}
              >
                {speakerMuted ? <VolumeX size={16} /> : <Volume2 size={16} />}
              </button>
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
