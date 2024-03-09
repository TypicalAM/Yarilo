import path from "path";
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	resolve: {
		alias: {
			$components: path.resolve("./src/lib/components"),
			$stores: path.resolve("./src/lib/stores"),
			$proto: path.resolve("./src/lib/proto"),
			$env: path.resolve("./src/lib/env"),
			$utils: path.resolve("./src/lib/utils")
		}
	}
});
