import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { basePath, nodeHandler } from './config.cjs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Mount on the Express adapter before Nest initializes its body parser.
  app.use(basePath, nodeHandler);
  await app.listen(3000, '127.0.0.1');
}
void bootstrap();
