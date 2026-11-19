import styles from "./YouTubePlayer.module.css";

interface YouTubePlayerProps {
  videoId: string;
  title?: string;
}

const YOUTUBE_ID_RE = /^[A-Za-z0-9_-]{6,20}$/;

export function YouTubePlayer({ videoId, title }: YouTubePlayerProps) {
  if (!YOUTUBE_ID_RE.test(videoId)) {
    return null;
  }
  return (
    <div className={styles.container}>
      <div className={styles.wrapper}>
        <iframe
          src={`https://www.youtube.com/embed/${videoId}`}
          title={title || "YouTube video"}
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
          allowFullScreen
          className={styles.iframe}
        />
      </div>
    </div>
  );
}
