"use client";
import React, { useState, useEffect } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Lock, Unlock, Key, Trash2, AlertCircle, LogOut, UserPlus, Shield } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Principal } from '@dfinity/principal';

interface EncryptedNote {
  id: number;
  content: string;
  timestamp: string;
}

interface Guardian {
  principalId: string;
  dateAdded: string;
  status: string;
}

interface GuardianKey {
  principalId: string;
  encryptedKey: number[];
  iv: number[];
  guardianPublicKey: number[];
}

const EncryptedNotes = () => {
  const [authClient, setAuthClient] = useState<AuthClient | null>(null);
  const [identity, setIdentity] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAuthClientReady, setIsAuthClientReady] = useState(false);
  const [note, setNote] = useState('');
  const [encryptionKey, setEncryptionKey] = useState('');
  const [encryptedNotes, setEncryptedNotes] = useState<EncryptedNote[]>([]);
  const [decryptedNote, setDecryptedNote] = useState('');
  const [error, setError] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const [backupGuardians, setBackupGuardians] = useState<Guardian[]>([]);
  const [newGuardianId, setNewGuardianId] = useState('');
  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [recoveryApprovals, setRecoveryApprovals] = useState<string[]>([]);
  const [backupEncryptionKey, setBackupEncryptionKey] = useState('');

  useEffect(() => {
    const initAuth = async () => {
      try {
        const client = await AuthClient.create();
        setAuthClient(client);
        setIsAuthClientReady(true);

        // 既存の認証状態をチェック
        if (await client.isAuthenticated()) {
          const identity = client.getIdentity();
          handleAuthSuccess(identity);
        }
      } catch (e) {
        console.error('AuthClient initialization failed:', e);
        setError('認証クライアントの初期化に失敗しました');
      }
    };

    initAuth();
  }, []);

  // 保存されたメモの読み込み
  useEffect(() => {
    if (isAuthenticated && identity) {
      const principal = identity.getPrincipal().toString();
      const savedNotes = localStorage.getItem(`encrypted-notes-${principal}`);
      if (savedNotes) {
        setEncryptedNotes(JSON.parse(savedNotes));
      }
    }
  }, [isAuthenticated, identity]);

  // メモの保存
  useEffect(() => {
    if (isAuthenticated && identity) {
      const principal = identity.getPrincipal().toString();
      localStorage.setItem(`encrypted-notes-${principal}`, JSON.stringify(encryptedNotes));
    }
  }, [encryptedNotes, isAuthenticated, identity]);

  // 認証成功時の処理
  const handleAuthSuccess = async (identity: any) => {
    setIdentity(identity);
    setIsAuthenticated(true);
    // Principalからユニークな暗号化キーを生成
    const principal = identity.getPrincipal().toString();
    const key = await generateKeyFromPrincipal(principal);
    setEncryptionKey(key);
  };

  // Principalから暗号化キーを生成
  const generateKeyFromPrincipal = async (principal: string): Promise<string> => {
    const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(principal));
    const array = Array.from(new Uint8Array(buffer));
    return array.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // II認証の開始
  const handleAuth = async () => {
    if (!authClient) {
      setError('認証クライアントが初期化されていません');
      return;
    }

    try {
      await authClient.login({
        identityProvider: process.env.NEXT_PUBLIC_II_URL || 'https://identity.ic0.app',
        derivationOrigin: window.location.origin,
        windowOpenerFeatures: "width=100%,height=100%,left=0,top=0",
        onSuccess: () => {
          const identity = authClient.getIdentity();
          handleAuthSuccess(identity);
        },
        onError: (error) => {
          console.error('Authentication error:', error);
          setError(`認証に失敗しました: ${error || '不明なエラー'}`);
        }
      });
    } catch (e) {
      console.error('Login error:', e);
      setError('認証プロセスでエラーが発生しました');
    }
  };

  // 暗号化処理
  const handleEncrypt = async () => {
    if (!note.trim()) return;
    
    setIsProcessing(true);
    setError('');

    if (!window.crypto || !window.crypto.subtle) {
      setError('このブラウザは暗号化をサポートしていません');
      setIsProcessing(false);
      return;
    }

    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(note);
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // 暗号化キーを32バイト（256ビット）に調整
      const keyBuffer = encoder.encode(encryptionKey);
      const hash = await crypto.subtle.digest('SHA-256', keyBuffer);
      
      const key = await crypto.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
      );

      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encrypted), iv.length);
      const encryptedBase64 = btoa(String.fromCharCode(...combined));

      const newNote: EncryptedNote = {
        id: Date.now(),
        content: encryptedBase64,
        timestamp: new Date().toISOString()
      };

      setEncryptedNotes(prev => [...prev, newNote]);
      setNote('');
    } catch (e) {
      setError('暗号化に失敗しました');
    } finally {
      setIsProcessing(false);
    }
  };

  // 復号化処理
  const handleDecrypt = async (noteId: number) => {
    setIsProcessing(true);
    setError('');

    if (!window.crypto || !window.crypto.subtle) {
      setError('このブラウザは復号化をサポートしていません');
      setIsProcessing(false);
      return;
    }

    try {
      const noteToDecrypt = encryptedNotes.find(n => n.id === noteId);
      if (!noteToDecrypt) {
        throw new Error('ノートが見つかりません');
      }

      const combined = new Uint8Array(
        atob(noteToDecrypt.content).split('').map(c => c.charCodeAt(0))
      );

      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      const encoder = new TextEncoder();
      const keyBuffer = encoder.encode(encryptionKey);
      const hash = await crypto.subtle.digest('SHA-256', keyBuffer);
      
      const key = await crypto.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
      );

      const decoder = new TextDecoder();
      setDecryptedNote(decoder.decode(decrypted));
    } catch (e) {
      setError('復号化に失敗しました');
      setDecryptedNote('');
    } finally {
      setIsProcessing(false);
    }
  };

  // ノートの削除
  const handleDelete = (noteId: number) => {
    setEncryptedNotes(prev => prev.filter(note => note.id !== noteId));
    setDecryptedNote('');
    setError('');
  };

  // バックアップガーディアンの読み込み
  useEffect(() => {
    if (isAuthenticated && identity) {
      const principal = identity.getPrincipal().toString();
      const savedGuardians = localStorage.getItem(`backup-guardians-${principal}`);
      if (savedGuardians) {
        setBackupGuardians(JSON.parse(savedGuardians));
      }

      const savedBackupKey = localStorage.getItem(`backup-key-${principal}`);
      if (savedBackupKey) {
        setBackupEncryptionKey(savedBackupKey);
      }
    }
  }, [isAuthenticated, identity]);

  // バックアップガーディアンの保存
  useEffect(() => {
    if (isAuthenticated && identity) {
      const principal = identity.getPrincipal().toString();
      localStorage.setItem(`backup-guardians-${principal}`, JSON.stringify(backupGuardians));
    }
  }, [backupGuardians, isAuthenticated, identity]);

  // バックアップガーディアンの追加
  const handleAddGuardian = async () => {
    try {
      const guardianPrincipal = Principal.fromText(newGuardianId);
      
      if (backupGuardians.some(g => g.principalId === newGuardianId)) {
        setError('このガーディアンは既に登録されています');
        return;
      }

      const newGuardian: Guardian = {
        principalId: newGuardianId,
        dateAdded: new Date().toISOString(),
        status: 'active'
      };

      setBackupGuardians(prev => [...prev, newGuardian]);
      setNewGuardianId('');

      const newBackupKey = await generateBackupKey();
      setBackupEncryptionKey(newBackupKey);
      
      if (identity) {
        const principal = identity.getPrincipal().toString();
        localStorage.setItem(`backup-key-${principal}`, newBackupKey);
      }

    } catch (e) {
      setError('無効なPrincipal IDです');
    }
  };

  // バックアップキーの生成
  const generateBackupKey = async (): Promise<string> => {
    const keyToBackup = encryptionKey;
    
    const guardianKeys: GuardianKey[] = await Promise.all(
      backupGuardians.map(async guardian => {
        const guardianKeyMaterial = new Uint8Array(32);
        crypto.getRandomValues(guardianKeyMaterial);
        const guardianKey = await crypto.subtle.importKey(
          'raw',
          guardianKeyMaterial,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedKey = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          guardianKey,
          new TextEncoder().encode(keyToBackup)
        );
        
        return {
          principalId: guardian.principalId,
          encryptedKey: Array.from(new Uint8Array(encryptedKey)),
          iv: Array.from(iv),
          guardianPublicKey: Array.from(guardianKeyMaterial)
        };
      })
    );
    
    return JSON.stringify(guardianKeys);
  };

  // リカバリーモードの開始
  const startRecoveryMode = () => {
    setIsRecoveryMode(true);
    setRecoveryApprovals([]);
  };

  // ガーディアンによる承認
  const handleGuardianApproval = async () => {
    if (!authClient) {
      setError('認証クライアントが初期化されていません');
      return;
    }

    if (!authClient.isAuthenticated()) {
      setError('承認にはログインが必要です');
      return;
    }

    const guardianIdentity = authClient.getIdentity();
    const guardianPrincipal = guardianIdentity.getPrincipal().toString();

    const isRegisteredGuardian = backupGuardians.some(
      g => g.principalId === guardianPrincipal
    );

    if (!isRegisteredGuardian) {
      setError('あなたはガーディアンとして登録されていません');
      return;
    }

    if (recoveryApprovals.includes(guardianPrincipal)) {
      setError('既に承認済みです');
      return;
    }

    setRecoveryApprovals(prev => [...prev, guardianPrincipal]);

    const requiredApprovals = Math.ceil(backupGuardians.length / 2);
    if (recoveryApprovals.length + 1 >= requiredApprovals) {
      await executeRecovery();
    }
  };

  // リカバリーの実行
  const executeRecovery = async () => {
    try {
      setIsProcessing(true);
      setEncryptionKey(backupEncryptionKey);
      setIsRecoveryMode(false);
      setRecoveryApprovals([]);
      setError('');
    } catch (e) {
      setError('リカバリーに失敗しました');
    } finally {
      setIsProcessing(false);
    }
  };

  // ログアウト
  const handleLogout = async () => {
    if (authClient) {
      await authClient.logout();
      setIsAuthenticated(false);
      setIdentity(null);
      setEncryptionKey('');
      setNote('');
      setDecryptedNote('');
      setError('');
      setEncryptedNotes([]);
    }
  };

  if (!isAuthenticated) {
    return (
      <Card className="w-full max-w-md mx-auto mt-8">
        <CardHeader>
          <CardTitle className="text-center">Internet Identity認証</CardTitle>
        </CardHeader>
        <CardContent className="text-center space-y-4">
          <p className="text-sm text-gray-500">
            Internet Identityを使用して安全に認証を行います。
            生体認証やセキュリティキーを使用できます。
          </p>
          <Button onClick={handleAuth} className="gap-2">
            <Key className="w-4 h-4" />
            Internet Identityで認証
          </Button>
        </CardContent>
      </Card>
    );
  }

  const renderBackupManagement = () => (
    <div className="space-y-4 mt-6">
      <h3 className="text-lg font-medium">バックアップガーディアン管理</h3>
      
      <div className="flex gap-2">
        <Input
          value={newGuardianId}
          onChange={(e) => setNewGuardianId(e.target.value)}
          placeholder="ガーディアンのPrincipal ID"
          className="flex-grow"
        />
        <Button 
          onClick={handleAddGuardian}
          disabled={!newGuardianId.trim()}
          className="gap-2"
        >
          <UserPlus className="w-4 h-4" />
          追加
        </Button>
      </div>

      {backupGuardians.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm text-gray-500">
            登録済みガーディアン ({backupGuardians.length}名)
          </p>
          {backupGuardians.map((guardian) => (
            <div key={guardian.principalId} 
                 className="flex items-center justify-between p-2 bg-gray-50 rounded">
              <code className="text-xs">{guardian.principalId}</code>
              <span className="text-xs text-gray-500">
                {new Date(guardian.dateAdded).toLocaleDateString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const renderRecoveryMode = () => (
    <div className="space-y-4">
      <Alert>
        <Shield className="w-4 h-4" />
        <AlertDescription>
          リカバリーモード: {recoveryApprovals.length} / {Math.ceil(backupGuardians.length / 2)} の承認
        </AlertDescription>
      </Alert>

      <Button
        onClick={handleGuardianApproval}
        disabled={isProcessing}
        className="w-full gap-2"
      >
        <Key className="w-4 h-4" />
        ガーディアンとして承認
      </Button>
    </div>
  );

  return (
    <Card className="w-full max-w-2xl mx-auto mt-8">
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>暗号化メモ</CardTitle>
          {identity && (
            <p className="text-sm text-gray-500 mt-1">
              Principal: {identity.getPrincipal().toString().slice(0, 10)}...
            </p>
          )}
        </div>
        <Button 
          variant="outline" 
          onClick={handleLogout}
          className="gap-2"
        >
          <LogOut className="w-4 h-4" />
          ログアウト
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="w-4 h-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {isRecoveryMode ? (
          renderRecoveryMode()
        ) : (
          <>
            <div className="space-y-2">
              <label className="text-sm font-medium">新規メモ</label>
              <Textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="暗号化したいテキストを入力..."
                className="min-h-[100px]"
              />
              <Button 
                onClick={handleEncrypt}
                disabled={!note.trim() || isProcessing}
                className="w-full gap-2"
              >
                <Lock className="w-4 h-4" />
                {isProcessing ? '処理中...' : '暗号化して保存'}
              </Button>
            </div>

            {encryptedNotes.length > 0 && (
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  保存された暗号化メモ ({encryptedNotes.length}件)
                </label>
                <div className="space-y-2">
                  {encryptedNotes.map((encNote) => (
                    <div key={encNote.id} 
                         className="flex items-center gap-2 p-2 bg-gray-50 rounded hover:bg-gray-100 transition-colors">
                      <div className="flex-grow font-mono text-xs truncate">
                        {encNote.content.slice(0, 50)}...
                      </div>
                      <div className="text-xs text-gray-500 whitespace-nowrap">
                        {new Date(encNote.timestamp).toLocaleString()}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDecrypt(encNote.id)}
                        disabled={isProcessing}
                        className="gap-1"
                      >
                        <Unlock className="w-4 h-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDelete(encNote.id)}
                        disabled={isProcessing}
                        className="text-red-500 gap-1"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {decryptedNote && (
              <div className="space-y-2">
                <label className="text-sm font-medium">復号化されたテキスト</label>
                <Textarea
                  value={decryptedNote}
                  readOnly
                  className="min-h-[100px]"
                />
              </div>
            )}

            {renderBackupManagement()}
          </>
        )}
      </CardContent>
    </Card>
  );
};

export default EncryptedNotes;
