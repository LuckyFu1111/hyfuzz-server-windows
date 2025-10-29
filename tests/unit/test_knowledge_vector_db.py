from src.knowledge.vector_db_manager import VectorDBManager

def test_vector_db_add_embedding():
    manager = VectorDBManager(embeddings={})
    manager.add_embedding("item", [0.1, 0.2])
    assert manager.embeddings["item"] == [0.1, 0.2]
