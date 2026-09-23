import { useState } from "react";
import { Chip } from "@/components/primitives";
import { useComments, useCreateComment, useDeleteComment } from "@/hooks/useComments";
import { useAuthStore } from "@/stores/authStore";
import styles from "./EntityComments.module.css";

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

interface EntityCommentsProps {
  commentableType: string;
  commentableId: string;
}

export function EntityComments({ commentableType, commentableId }: EntityCommentsProps) {
  const { data: comments } = useComments(commentableType, commentableId);
  const createComment = useCreateComment();
  const deleteComment = useDeleteComment();
  const [content, setContent] = useState("");
  // The API only lets the author (or an admin) delete a comment
  const currentUser = useAuthStore((s) => s.user);
  const canDelete = (authorId: string | null | undefined) =>
    currentUser?.role === "admin" || (authorId != null && authorId === currentUser?.id);

  const handleSubmit = () => {
    const trimmed = content.trim();
    if (!trimmed) return;
    createComment.mutate(
      { commentable_type: commentableType, commentable_id: commentableId, content: trimmed },
      { onSuccess: () => setContent("") }
    );
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className={styles.wrapper}>
      <div className={styles.header}>
        Comments <Chip pill>{comments?.length ?? 0}</Chip>
      </div>
      <div className={styles.body}>
        {comments && comments.length > 0 ? (
          <div className={styles.commentList}>
            {comments.map((comment) => (
              <div key={comment.id} className={styles.comment}>
                <div className={styles.avatar}>
                  {(comment.username || comment.user_id || "?").charAt(0).toUpperCase()}
                </div>
                <div className={styles.commentBody}>
                  <div className={styles.commentMeta}>
                    <span className={styles.commentUser}>{comment.username || comment.user_id}</span>
                    <span className={styles.commentTime}>{timeAgo(comment.created_at)}</span>
                    {canDelete(comment.user_id) && (
                      <button
                        className={styles.deleteBtn}
                        onClick={() => deleteComment.mutate(comment.id)}
                        title="Delete comment"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                  <div className={styles.commentContent}>{comment.content}</div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className={styles.empty}>No comments yet</div>
        )}
        <div className={styles.inputArea}>
          <textarea
            className={styles.input}
            placeholder="Add a comment..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={1}
          />
          <button
            className={styles.submitBtn}
            onClick={handleSubmit}
            disabled={!content.trim() || createComment.isPending}
          >
            Post
          </button>
        </div>
      </div>
    </div>
  );
}
