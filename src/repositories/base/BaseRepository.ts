import { Repository, EntityTarget, FindOptionsWhere, FindManyOptions, FindOneOptions, ObjectLiteral } from 'typeorm';
import { AppDataSource } from '../../config/orm';

export abstract class BaseRepository<T extends ObjectLiteral> {
  protected repository: Repository<T>;

  constructor(entity: EntityTarget<T>) {
    this.repository = AppDataSource.getRepository(entity);
  }

  async findById(id: string): Promise<T | null> {
    return this.repository.findOne({ where: { id } as unknown as FindOptionsWhere<T> });
  }

  async findOne(options: FindOneOptions<T>): Promise<T | null> {
    return this.repository.findOne(options);
  }

  async findMany(options: FindManyOptions<T>): Promise<T[]> {
    return this.repository.find(options);
  }

  async findAll(): Promise<T[]> {
    return this.repository.find();
  }

  async create(data: Partial<T>): Promise<T> {
    const entity = this.repository.create(data as any);
    const saved = await this.repository.save(entity);
    return Array.isArray(saved) ? saved[0] : saved;
  }

  async update(id: string, data: Partial<T>): Promise<T | null> {
    await this.repository.update(id, data as any);
    return this.findById(id);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return (result.affected ?? 0) > 0;
  }

  async count(options?: FindManyOptions<T>): Promise<number> {
    return this.repository.count(options);
  }

  async exists(options: FindOneOptions<T>): Promise<boolean> {
    const count = await this.repository.count(options);
    return count > 0;
  }
}
