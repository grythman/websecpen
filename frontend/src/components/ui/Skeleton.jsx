import React from 'react';
import './Skeleton.css';

const Skeleton = ({ width = '100%', height = 16, circle = false, style = {} }) => {
  return (
    <div
      className="skeleton"
      style={{ width, height, borderRadius: circle ? '50%' : 'var(--radius-md)', ...style }}
    />
  );
};

export default Skeleton;
