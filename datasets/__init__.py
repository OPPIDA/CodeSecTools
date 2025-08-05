from datasets.BenchmarkJava.dataset import BenchmarkJava
from datasets.CVEfixes.dataset import CVEfixes
from datasets.SemgrepTest.dataset import SemgrepTest

DATASETS_ALL = {
    BenchmarkJava.name: BenchmarkJava,
    SemgrepTest.name: SemgrepTest,
    CVEfixes.name: CVEfixes,
}
