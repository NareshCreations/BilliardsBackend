import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { UserSession } from './UserSession.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ name: 'password_hash' })
  passwordHash: string;

  @Column({ name: 'first_name' })
  firstName: string;

  @Column({ name: 'last_name' })
  lastName: string;

  @Column({ name: 'date_of_birth', type: 'date', nullable: true })
  dateOfBirth: Date;

  @Column({ name: 'email_verified', default: false })
  emailVerified: boolean;

  @Column({ name: 'phone_verified', default: false })
  phoneVerified: boolean;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'is_premium', default: false })
  isPremium: boolean;

  @Column({ name: 'account_type', default: 'player' })
  accountType: 'player' | 'admin';

  @Column({ name: 'last_login', type: 'timestamp', nullable: true })
  lastLogin: Date;

  @Column({ name: 'last_ip', nullable: true })
  lastIp: string;

  @Column({ name: 'login_attempts', default: 0 })
  loginAttempts: number;

  @Column({ name: 'locked_until', type: 'timestamp', nullable: true })
  lockedUntil: Date | null;

  @Column({ name: 'password_reset_token', type: 'varchar', nullable: true })
  passwordResetToken: string | null;

  @Column({ name: 'password_reset_expires', type: 'timestamp', nullable: true })
  passwordResetExpires: Date | null;

  @Column({ name: 'email_verification_token', type: 'varchar', nullable: true })
  emailVerificationToken: string | null;

  @Column({ name: 'email_verification_expires', type: 'timestamp', nullable: true })
  emailVerificationExpires: Date | null;

  @Column({ name: 'phone_verification_code', type: 'varchar', nullable: true })
  phoneVerificationCode: string | null;

  @Column({ name: 'password_changed_at', type: 'timestamp', nullable: true })
  passwordChangedAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => UserSession, session => session.user)
  sessions: UserSession[];
}
