import styles from "./YouTubePlayer.module.css";

interface YouTubePlayerProps {
  videoId: string;
  title?: string;
}

export function YouTubePlayer({ videoId, title }: YouTubePlayerProps) {
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
