import styles from "./accessDenied.module.scss";

const accessDeniedPage = () => {
  return (
    <div className={styles.pageContainer}>
      <h1 className={styles.title}>Access Denied</h1>
    </div>
  );
};

export default accessDeniedPage;
