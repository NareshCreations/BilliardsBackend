import { FindOptionsWhere, FindManyOptions, FindOneOptions } from 'typeorm';

export interface BaseRepositoryInterface<T> {
  findById(id: string): Promise<T | null>;
  findOne(options: FindOneOptions<T>): Promise<T | null>;
  findMany(options: FindManyOptions<T>): Promise<T[]>;
  findAll(): Promise<T[]>;
  create(data: Partial<T>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T | null>;
  delete(id: string): Promise<boolean>;
  count(options?: FindManyOptions<T>): Promise<number>;
  exists(options: FindOneOptions<T>): Promise<boolean>;
}
