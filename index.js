// ============================================
// 必要なモジュールのインポート
// ============================================
import express from "express"; // Expressフレームワーク
import fs from "fs"; // ファイルシステム操作
import basicAuth from "basic-auth"; // Basic認証の処理

// ============================================
// Expressアプリケーションの初期化
// ============================================
const app = express();
app.use(express.json()); // JSONリクエストボディをパースするミドルウェア
const USERS_FILE = "./users.json"; // ユーザー情報を保存するJSONファイルのパス

// ============================================
// ユーティリティ関数
// ============================================

/**
 * ユーザー情報をJSONファイルから読み込む
 * @returns {Array} ユーザー情報の配列
 */
const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));

/**
 * ユーザー情報をJSONファイルに書き込む
 * @param {Array} data - 書き込むユーザー情報の配列
 */
const writeUsers = (data) =>
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

/**
 * Basic認証を行う関数
 * リクエストヘッダーから認証情報を取得し、users.jsonと照合する
 * @param {Object} req - Expressリクエストオブジェクト
 * @returns {Object|null} 認証成功時はユーザーオブジェクト、失敗時はnull
 */
function auth(req) {
  const credentials = basicAuth(req); // Basic認証の資格情報を取得
  if (!credentials) return null; // 認証情報が存在しない場合はnullを返す
  const users = readUsers(); // ユーザーリストを読み込む
  const user = users.find(
    (u) => u.user_id === credentials.name && u.password === credentials.pass
  ); // user_idとpasswordが一致するユーザーを検索
  return user || null; // 見つかった場合はユーザーオブジェクト、見つからない場合はnull
}

// ============================================
// エンドポイント: POST /signup
// 新規ユーザーアカウントを作成する
// ============================================
app.post("/signup", (req, res) => {
  const { user_id, password } = req.body; // リクエストボディからuser_idとpasswordを取得
  const users = readUsers(); // 既存のユーザーリストを読み込む

  // 必須チェック: user_idとpasswordが両方存在するか確認
  if (!user_id || !password) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Required user_id and password",
    });
  }

  // 長さチェック
  // user_id: 6文字以上20文字以下
  // password: 8文字以上20文字以下
  if (
    user_id.length < 6 ||
    user_id.length > 20 ||
    password.length < 8 ||
    password.length > 20
  ) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Input Length is incorrect",
    });
  }

  // 文字種チェック
  // user_id: 英数字のみ許可（A-Z, a-z, 0-9）
  // password: ASCII印字可能文字（0x21-0x7E）を許可（記号を含む）
  const idPattern = /^[A-Za-z0-9]+$/;
  const pwPattern = /^[\x21-\x7E]+$/; // ASCII記号含む
  if (!idPattern.test(user_id) || !pwPattern.test(password)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Incorrect character pattern",
    });
  }

  // 重複チェック: 同じuser_idが既に使用されていないか確認
  if (users.some((u) => u.user_id === user_id)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Already same user_id is used",
    });
  }

  // 新規ユーザーを作成して追加
  // nicknameの初期値はuser_id、commentの初期値は空文字列
  const newUser = { user_id, password, nickname: user_id, comment: "" };
  users.push(newUser);
  writeUsers(users); // ファイルに保存

  // 成功レスポンスを返す
  res.json({
    message: "Account successfully created",
    user: { user_id, nickname: user_id },
  });
});

// ============================================
// エンドポイント: GET /users/:user_id
// 指定されたuser_idのユーザー情報を取得する
// ============================================
app.get("/users/:user_id", (req, res) => {
  const targetId = req.params.user_id; // URLパラメータから対象のuser_idを取得
  const authedUser = auth(req); // Basic認証を実行

  // 認証失敗: 認証情報が無効または存在しない場合
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const users = readUsers(); // ユーザーリストを読み込む
  const user = users.find((u) => u.user_id === targetId); // 対象のuser_idを持つユーザーを検索

  // ユーザーが存在しない: 指定されたuser_idのユーザーが見つからない場合
  if (!user) {
    return res.status(404).json({ message: "No user found" });
  }

  // nickname / comment の既定値処理
  // nicknameが未設定の場合はuser_idを、commentが未設定の場合は空文字列を使用
  const nickname = user.nickname || user.user_id;
  const comment = user.comment || "";

  // ユーザー情報を返す（commentが空の場合はレスポンスに含めない）
  res.json({
    message: "User details by user_id",
    user: {
      user_id: user.user_id,
      nickname,
      ...(comment ? { comment } : {}), // commentが空なら省略
    },
  });
});

// ============================================
// エンドポイント: PATCH /users/:user_id
// 指定されたuser_idのユーザー情報を更新する（nicknameとcommentのみ）
// ============================================
app.patch("/users/:user_id", (req, res) => {
  const targetId = req.params.user_id; // URLパラメータから対象のuser_idを取得
  const authedUser = auth(req); // Basic認証を実行

  // 認証失敗: 認証情報が無効または存在しない場合
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  // 権限チェック: 認証されたユーザーと更新対象のuser_idが一致するか確認
  // 他人のアカウント情報は更新できない
  if (authedUser.user_id !== targetId) {
    return res.status(403).json({ message: "No permission for update" });
  }

  const users = readUsers(); // ユーザーリストを読み込む
  const userIndex = users.findIndex((u) => u.user_id === targetId); // 更新対象のユーザーのインデックスを取得
  if (userIndex === -1) {
    return res.status(404).json({ message: "No user found" }); // ユーザーが存在しない場合
  }

  const { nickname, comment, user_id, password } = req.body; // リクエストボディから更新情報を取得

  // user_id/passwordの変更は禁止: セキュリティ上の理由で変更不可
  if (user_id || password) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Not updatable user_id and password",
    });
  }

  // 必須チェック: nicknameまたはcommentのいずれかが指定されている必要がある
  if (nickname === undefined && comment === undefined) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Required nickname or comment",
    });
  }

  // 文字数チェック
  // nickname: 30文字以下
  // comment: 100文字以下
  if ((nickname && nickname.length > 30) || (comment && comment.length > 100)) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "String length limit exceeded or containing invalid characters",
    });
  }

  // 更新処理
  // nickname: 空文字列の場合はuser_idを設定（デフォルト値に戻す）
  // comment: 空文字列の場合は空文字列を設定
  if (nickname !== undefined) {
    users[userIndex].nickname = nickname === "" ? targetId : nickname;
  }
  if (comment !== undefined) {
    users[userIndex].comment = comment === "" ? "" : comment;
  }

  writeUsers(users); // ファイルに保存

  // 更新後のユーザー情報を返す
  res.json({
    message: "User successfully updated",
    user: {
      user_id: users[userIndex].user_id,
      nickname: users[userIndex].nickname,
      comment: users[userIndex].comment,
    },
  });
});

// ============================================
// エンドポイント: POST /close
// 認証されたユーザーのアカウントを削除する
// ============================================
app.post("/close", (req, res) => {
  const authedUser = auth(req); // Basic認証を実行
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" }); // 認証失敗
  }

  const users = readUsers(); // ユーザーリストを読み込む
  // 認証されたユーザーをリストから除外（アカウント削除）
  const newUsers = users.filter((u) => u.user_id !== authedUser.user_id);
  writeUsers(newUsers); // ファイルに保存

  // 削除成功のレスポンスを返す
  res.json({
    message: "Account and user successfully removed",
  });
});

// ============================================
// サーバーの起動
// ============================================
app.listen(3000, () => console.log("Server running on port 3000"));
