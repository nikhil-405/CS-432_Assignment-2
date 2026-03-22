import random
import time
import matplotlib.pyplot as plt

from database.bplustree import BPlusTree
from database.bruteforce import BruteForceDB


class PerformanceAnalyzer:
    def __init__(self, tree_degree=50, seed=42):
        self.tree_degree = tree_degree
        self.rng = random.Random(seed)

    def _measure_insert(self, keys):
        bpt = BPlusTree(t=self.tree_degree)
        brute = BruteForceDB()

        start = time.perf_counter()
        for key in keys:
            bpt.insert(key, f"val_{key}")
        bplus_time = time.perf_counter() - start

        start = time.perf_counter()
        for key in keys:
            brute.insert(key)
        brute_time = time.perf_counter() - start

        return bpt, brute, bplus_time, brute_time

    def _measure_search(self, bpt, brute, key_space, search_count):
        search_keys = self.rng.sample(range(key_space), search_count)

        start = time.perf_counter()
        for key in search_keys:
            bpt.search(key)
        bplus_time = time.perf_counter() - start

        start = time.perf_counter()
        for key in search_keys:
            brute.search(key)
        brute_time = time.perf_counter() - start

        return bplus_time, brute_time

    def _measure_range_query(self, bpt, brute, key_space, query_count, span):
        ranges = []
        max_start = max(0, key_space - span - 1)
        for _ in range(query_count):
            start = self.rng.randint(0, max_start)
            end = start + span
            ranges.append((start, end))

        start = time.perf_counter()
        for low, high in ranges:
            bpt.range_query(low, high)
        bplus_time = time.perf_counter() - start

        start = time.perf_counter()
        for low, high in ranges:
            brute.range_query(low, high)
        brute_time = time.perf_counter() - start

        return bplus_time, brute_time

    def _measure_delete(self, bpt, brute, keys, delete_count):
        delete_keys = self.rng.sample(keys, delete_count)

        start = time.perf_counter()
        for key in delete_keys:
            bpt.delete(key)
        bplus_time = time.perf_counter() - start

        start = time.perf_counter()
        for key in delete_keys:
            brute.delete(key)
        brute_time = time.perf_counter() - start

        return bplus_time, brute_time

    def run_tests(
        self,
        sizes=None,
        search_count=200,
        range_query_count=80,
        delete_count=200,
    ):
        if sizes is None:
            sizes = list(range(100, 100000, 1000))

        results = {
            "sizes": [],
            "insert": {"bplus": [], "bruteforce": []},
            "search": {"bplus": [], "bruteforce": []},
            "range_query": {"bplus": [], "bruteforce": []},
            "delete": {"bplus": [], "bruteforce": []},
        }

        for size in sizes:
            key_space = size * 10
            keys = self.rng.sample(range(key_space), size)

            bpt, brute, bplus_insert, brute_insert = self._measure_insert(keys)

            current_search_count = min(search_count, key_space)
            bplus_search, brute_search = self._measure_search(
                bpt,
                brute,
                key_space,
                current_search_count,
            )

            span = max(5, size // 20)
            bplus_range, brute_range = self._measure_range_query(
                bpt,
                brute,
                key_space,
                range_query_count,
                span,
            )

            current_delete_count = min(delete_count, len(keys))
            bplus_delete, brute_delete = self._measure_delete(
                bpt,
                brute,
                keys,
                current_delete_count,
            )

            results["sizes"].append(size)
            results["insert"]["bplus"].append(bplus_insert)
            results["insert"]["bruteforce"].append(brute_insert)
            results["search"]["bplus"].append(bplus_search)
            results["search"]["bruteforce"].append(brute_search)
            results["range_query"]["bplus"].append(bplus_range)
            results["range_query"]["bruteforce"].append(brute_range)
            results["delete"]["bplus"].append(bplus_delete)
            results["delete"]["bruteforce"].append(brute_delete)

        return results

    def plot_results(self, results, save_prefix=None, show=True):
        sizes = results["sizes"]
        operations = [
            ("insert", "Insertion Time (s)"),
            ("search", "Search Time (s)"),
            ("range_query", "Range Query Time (s)"),
            ("delete", "Deletion Time (s)"),
        ]

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        axes = axes.ravel()

        for idx, (operation, ylabel) in enumerate(operations):
            axes[idx].plot(sizes, results[operation]["bplus"], label="B+ Tree", marker="o")
            axes[idx].plot(
                sizes,
                results[operation]["bruteforce"],
                label="Brute Force",
                marker="s",
            )
            axes[idx].set_title(operation.replace("_", " ").title())
            axes[idx].set_xlabel("Number of Keys")
            axes[idx].set_ylabel(ylabel)
            axes[idx].grid(True, linestyle="--", alpha=0.4)
            axes[idx].legend()

        fig.tight_layout()

        if save_prefix:
            fig.savefig(f"{save_prefix}_performance.png", dpi=160)

        if show:
            plt.show()

        return fig


if __name__ == "__main__":
    analyzer = PerformanceAnalyzer(tree_degree=50, seed=42)
    quick_sizes = list(range(100, 20100, 2000))
    benchmark_results = analyzer.run_tests(sizes=quick_sizes)
    analyzer.plot_results(benchmark_results, save_prefix="database", show=True)
