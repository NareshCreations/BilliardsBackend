import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { User } from './User.entity';

@Entity('user_sessions')
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @Column({ name: 'refresh_token_hash' })
  refreshTokenHash: string;

  @Column({ type: 'jsonb', name: 'device_info' })
  deviceInfo: any;

  @Column({ name: 'ip_address' })
  ipAddress: string;

  @Column({ name: 'user_agent' })
  userAgent: string;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'expires_at', type: 'timestamp' })
  expiresAt: Date;

  @Column({ name: 'last_used_at', type: 'timestamp', nullable: true })
  lastUsedAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @ManyToOne(() => User, user => user.sessions)
  @JoinColumn({ name: 'user_id' })
  user: User;
}
