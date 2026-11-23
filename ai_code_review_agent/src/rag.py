"""Milestone 1 - Secure Coding Knowledge Base + RAG pipeline.
Chunking -> TF-IDF (1-2 gram) embedding -> persisted vector index -> cosine retrieval."""
import hashlib
import pickle
import re
from dataclasses import dataclass
from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from . import config


@dataclass
class Chunk:
    source: str
    heading: str
    text: str


def chunk_markdown(source: str, md: str, max_words: int = 140) -> List[Chunk]:
    title = re.search(r"^# (.+)$", md, re.M)
    title = title.group(1) if title else source
    chunks = []
    for block in re.split(r"^## ", md, flags=re.M)[1:]:
        heading, _, body = block.partition("\n")
        words = body.split()
        for i in range(0, max(len(words), 1), max_words - 20):   # 20-word overlap
            part = " ".join(words[i:i + max_words])
            if part:
                chunks.append(Chunk(source, f"{title} - {heading.strip()}", part))
    return chunks


class KnowledgeBase:
    def __init__(self):
        self.chunks: List[Chunk] = []
        self.vectorizer = None
        self.matrix = None
        self._load_or_build()

    # -- indexing ---------------------------------------------------------
    def _signature(self) -> str:
        h = hashlib.md5()
        for p in sorted(config.KB_DIR.glob("*.md")):
            h.update(p.name.encode() + p.read_bytes())
        return h.hexdigest()

    def _load_or_build(self):
        sig = self._signature()
        if config.INDEX_PATH.exists():
            try:
                data = pickle.loads(config.INDEX_PATH.read_bytes())
                if data["sig"] == sig:
                    self.chunks, self.vectorizer, self.matrix = data["chunks"], data["vec"], data["mat"]
                    return
            except Exception:
                pass
        self.build(sig)

    def build(self, sig: str = None):
        self.chunks = []
        for p in sorted(config.KB_DIR.glob("*.md")):
            self.chunks += chunk_markdown(p.name, p.read_text(encoding="utf-8"))
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", sublinear_tf=True)
        self.matrix = self.vectorizer.fit_transform([f"{c.heading} {c.text}" for c in self.chunks])
        try:
            config.DATA_DIR.mkdir(exist_ok=True)
            config.INDEX_PATH.write_bytes(pickle.dumps(
                {"sig": sig or self._signature(), "chunks": self.chunks, "vec": self.vectorizer, "mat": self.matrix}))
        except OSError:
            pass

    # -- retrieval --------------------------------------------------------
    def search(self, query: str, k: int = 3, min_score: float = 0.05):
        q = self.vectorizer.transform([query])
        scores = linear_kernel(q, self.matrix).ravel()
        order = scores.argsort()[::-1][:k]
        return [(self.chunks[i], float(scores[i])) for i in order if scores[i] >= min_score]
