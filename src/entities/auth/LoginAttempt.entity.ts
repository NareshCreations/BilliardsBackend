import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('login_attempts')
export class LoginAttempt {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  email: string;

  @Column({ name: 'ip_address' })
  ipAddress: string;

  @Column({ name: 'user_agent' })
  userAgent: string;

  @Column()
  success: boolean;

  @Column({ name: 'failure_reason', nullable: true })
  failureReason: string;

  @CreateDateColumn({ name: 'attempted_at' })
  attemptedAt: Date;
}
