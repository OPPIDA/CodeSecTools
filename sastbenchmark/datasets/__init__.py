from sastbenchmark.datasets.BenchmarkJava.dataset import BenchmarkJava
from sastbenchmark.datasets.CVEfixes.dataset import CVEfixes
from sastbenchmark.datasets.SemgrepTest.dataset import SemgrepTest

DATASETS_ALL = {
    BenchmarkJava.name: BenchmarkJava,
    SemgrepTest.name: SemgrepTest,
    CVEfixes.name: CVEfixes,
}
