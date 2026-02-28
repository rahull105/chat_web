export type ChatType = 'direct' | 'group';

export interface User {
  id: string;
  name: string;
  email: string;
  about: string;
  avatarColor: string;
  createdAt: string;
  lastSeen: string | null;
}

export interface Attachment {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  url: string;
}

export interface MessageReaction {
  emoji: string;
  userIds: string[];
}

export interface MessageEncryption {
  algorithm: 'AES-GCM';
  iv: string;
}

export interface SeenBy {
  userId: string;
  at: string;
}

export interface ReplyToMessage {
  id: string;
  text: string;
  senderId: string;
  senderName: string;
}

export interface Message {
  id: string;
  chatId: string;
  senderId: string;
  text: string;
  attachments: Attachment[];
  replyTo: string | null;
  createdAt: string;
  editedAt: string | null;
  isDeleted: boolean;
  seenBy: SeenBy[];
  reactions: MessageReaction[];
  pinnedBy: string[];
  pinnedAt: string | null;
  encryption: MessageEncryption | null;
  sender: User | null;
  replyToMessage: ReplyToMessage | null;
}

export interface Chat {
  id: string;
  type: ChatType;
  name: string | null;
  description: string;
  members: User[];
  admins: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  lastMessageAt: string;
  avatarColor: string;
  title: string;
  subtitle: string;
  directPeer: User | null;
  unreadCount: number;
  pinnedCount: number;
  lastMessage: Message | null;
}

export interface StatusItem {
  id: string;
  userId: string;
  text: string;
  attachment: Attachment | null;
  createdAt: string;
  expiresAt: string;
  viewers: string[];
  user: User | null;
  seen: boolean;
}
