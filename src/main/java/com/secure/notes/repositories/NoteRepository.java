package com.secure.notes.repositories;

import com.secure.notes.models.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoteRepository extends JpaRepository<Note, Long> {
    //메서드 이름만 규칙에 맞춰서 인터페이스를 구현하는 느낌으로만 만들어두면 알아서 구현이 된다
    List<Note> findByOwnerUsername(String username);
}