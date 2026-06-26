/*
 * CommentSection — Comments thread with add/delete functionality
 */
import React, { useState, useCallback } from 'react';
import {
  EuiTextArea,
  EuiButton,
  EuiButtonIcon,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
} from '@elastic/eui';
import { CaseComment } from '../../common/types';

interface Props {
  comments: CaseComment[];
  onAddComment: (content: string) => Promise<void>;
  onDeleteComment: (commentId: string) => Promise<void>;
  currentUser?: string;
}

export const CommentSection: React.FC<Props> = ({
  comments,
  onAddComment,
  onDeleteComment,
  currentUser = 'analyst',
}) => {
  const [newComment, setNewComment] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = useCallback(async () => {
    if (!newComment.trim()) return;
    setSubmitting(true);
    try {
      await onAddComment(newComment.trim());
      setNewComment('');
    } finally {
      setSubmitting(false);
    }
  }, [newComment, onAddComment]);

  const sortedComments = [...comments].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );

  return (
    <div className="caseManagement__comments">
      {/* Add comment form */}
      <div className="caseManagement__comments__form">
        <EuiTextArea
          id="add-comment-textarea"
          placeholder="Add a comment..."
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          rows={3}
          fullWidth
          compressed
        />
        <EuiSpacer size="s" />
        <EuiFlexGroup justifyContent="flexEnd">
          <EuiFlexItem grow={false}>
            <EuiButton
              id="submit-comment-btn"
              size="s"
              fill
              onClick={handleSubmit}
              isLoading={submitting}
              disabled={!newComment.trim()}
              className="caseManagement__button--primary"
            >
              Add Comment
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </div>

      <EuiSpacer size="l" />

      {/* Comments list */}
      {sortedComments.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 20, color: '#64748b', fontSize: 13 }}>
          No comments yet. Be the first to add one.
        </div>
      ) : (
        sortedComments.map((comment) => (
          <div key={comment.comment_id} className="caseManagement__comments__item">
            <div className="caseManagement__comments__item__header">
              <span className="caseManagement__comments__item__author">
                {comment.author}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="caseManagement__comments__item__time">
                  {new Date(comment.created_at).toLocaleString()}
                </span>
                <EuiButtonIcon
                  id={`delete-comment-${comment.comment_id}`}
                  iconType="trash"
                  color="danger"
                  size="s"
                  aria-label="Delete comment"
                  onClick={() => onDeleteComment(comment.comment_id)}
                />
              </div>
            </div>
            <div className="caseManagement__comments__item__content">
              {comment.content}
            </div>
          </div>
        ))
      )}
    </div>
  );
};
