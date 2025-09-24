export interface UserResponseDto {
  id: string;
  email: string;
  phone?: string;
  firstName: string;
  lastName: string;
  dateOfBirth?: Date;
  emailVerified: boolean;
  phoneVerified: boolean;
  isActive: boolean;
  isPremium: boolean;
  accountType: string;
  lastLogin?: Date;
  createdAt: Date;
}
